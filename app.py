from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import requests
import time
import json
import os
from datetime import datetime, timedelta
from functools import wraps
import hashlib
from requests.exceptions import RequestException, Timeout, ConnectionError
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')

# ---- Configuration ----
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache"
}

# Configuration constants
OUTFITS_PER_PAGE = 50
THUMB_CHUNK = 20
REQUEST_TIMEOUT = 15
MAX_PAGES = 20
RETRY_ATTEMPTS = 3
RETRY_DELAY = 1
CACHE_DURATION = 300  # 5 minutes
MAX_SEARCHES_PER_HOUR = 30

# Simple in-memory cache for user data
user_cache = {}
search_history = {}
rate_limit_cache = {}

# ---- Rate Limiting & Caching ----
def get_client_ip():
    """Get client IP address for rate limiting"""
    return request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)

def rate_limit_check():
    """Check if client has exceeded search rate limit"""
    client_ip = get_client_ip()
    now = datetime.now()
    hour_key = now.strftime('%Y-%m-%d-%H')
    
    if client_ip not in rate_limit_cache:
        rate_limit_cache[client_ip] = {}
    
    if hour_key not in rate_limit_cache[client_ip]:
        rate_limit_cache[client_ip][hour_key] = 0
    
    # Clean old entries
    for ip in list(rate_limit_cache.keys()):
        for key in list(rate_limit_cache[ip].keys()):
            if key < (now - timedelta(hours=2)).strftime('%Y-%m-%d-%H'):
                del rate_limit_cache[ip][key]
    
    return rate_limit_cache[client_ip][hour_key] < MAX_SEARCHES_PER_HOUR

def increment_rate_limit():
    """Increment rate limit counter for client"""
    client_ip = get_client_ip()
    hour_key = datetime.now().strftime('%Y-%m-%d-%H')
    
    if client_ip not in rate_limit_cache:
        rate_limit_cache[client_ip] = {}
    if hour_key not in rate_limit_cache[client_ip]:
        rate_limit_cache[client_ip][hour_key] = 0
    
    rate_limit_cache[client_ip][hour_key] += 1

def get_cache_key(username):
    """Generate cache key for user data"""
    return hashlib.md5(username.lower().encode()).hexdigest()

def get_cached_data(username):
    """Get cached user data if available and not expired"""
    cache_key = get_cache_key(username)
    if cache_key in user_cache:
        cached_data, timestamp = user_cache[cache_key]
        if datetime.now() - timestamp < timedelta(seconds=CACHE_DURATION):
            logger.info(f"Cache hit for user: {username}")
            return cached_data
        else:
            del user_cache[cache_key]
    return None

def set_cached_data(username, data):
    """Cache user data with timestamp"""
    cache_key = get_cache_key(username)
    user_cache[cache_key] = (data, datetime.now())
    logger.info(f"Cached data for user: {username}")

# ---- Enhanced Helper Functions ----
def make_request_with_retry(url, method='GET', **kwargs):
    """Make HTTP request with retry logic and better error handling"""
    for attempt in range(RETRY_ATTEMPTS):
        try:
            if method.upper() == 'POST':
                response = requests.post(url, timeout=REQUEST_TIMEOUT, **kwargs)
            else:
                response = requests.get(url, timeout=REQUEST_TIMEOUT, **kwargs)
            
            if response.status_code == 200:
                return response
            elif response.status_code == 429:  # Rate limited
                wait_time = min(2 ** attempt, 10)
                logger.warning(f"Rate limited, waiting {wait_time}s before retry {attempt + 1}")
                time.sleep(wait_time)
            else:
                logger.warning(f"HTTP {response.status_code} on attempt {attempt + 1}: {url}")
                
        except (Timeout, ConnectionError) as e:
            logger.warning(f"Network error on attempt {attempt + 1}: {str(e)}")
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
        except Exception as e:
            logger.error(f"Unexpected error on attempt {attempt + 1}: {str(e)}")
            break
    
    return None

def get_user_info(username):
    """Get comprehensive user information including profile details"""
    if not username:
        return None
    
    # Get user ID first
    url = "https://users.roblox.com/v1/usernames/users"
    payload = {"usernames": [username], "excludeBannedUsers": False}
    
    response = make_request_with_retry(url, method='POST', json=payload, headers=HEADERS)
    if not response:
        return None
    
    try:
        data = response.json()
        if not data.get("data") or len(data["data"]) == 0:
            return None
        
        user_basic = data["data"][0]
        user_id = user_basic.get("id")
        
        # Get additional user details
        profile_url = f"https://users.roblox.com/v1/users/{user_id}"
        profile_response = make_request_with_retry(profile_url, headers=HEADERS)
        
        user_info = {
            "id": user_id,
            "username": user_basic.get("name"),
            "displayName": user_basic.get("displayName"),
            "hasVerifiedBadge": user_basic.get("hasVerifiedBadge", False),
            "created": None,
            "description": None
        }
        
        if profile_response:
            try:
                profile_data = profile_response.json()
                user_info.update({
                    "created": profile_data.get("created"),
                    "description": profile_data.get("description", "")
                })
            except:
                pass
        
        return user_info
        
    except Exception as e:
        logger.error(f"Error parsing user info: {str(e)}")
        return None

def fetch_all_outfits_enhanced(user_id, items_per_page=OUTFITS_PER_PAGE, max_pages=MAX_PAGES):
    """Enhanced outfit fetching with better error handling and metadata"""
    if not user_id:
        return []
    
    outfits = []
    page = 1
    total_pages = 1
    
    while page <= max_pages:
        url = f"https://avatar.roblox.com/v1/users/{user_id}/outfits"
        params = {"itemsPerPage": items_per_page, "page": page}
        
        response = make_request_with_retry(url, headers=HEADERS, params=params)
        if not response:
            logger.error(f"Failed to fetch outfits page {page}")
            break
        
        try:
            data = response.json()
            page_items = data.get("data", [])
            
            # Get pagination info on first page
            if page == 1:
                total_pages = min(data.get("totalPages", 1), max_pages)
                logger.info(f"Found {data.get('totalResults', 0)} total outfits across {total_pages} pages")
            
            if not page_items:
                break
            
            # Enrich outfit data
            for outfit in page_items:
                outfit['fetched_at'] = datetime.now().isoformat()
                outfit['page'] = page
            
            outfits.extend(page_items)
            
            if len(page_items) < items_per_page or page >= total_pages:
                break
                
            page += 1
            time.sleep(0.2)  # Polite delay
            
        except Exception as e:
            logger.error(f"Error parsing outfits page {page}: {str(e)}")
            break
    
    logger.info(f"Successfully collected {len(outfits)} outfits")
    return outfits

def fetch_outfit_thumbnails_enhanced(outfit_ids, size="420x420"):
    """Enhanced thumbnail fetching with better error handling"""
    results = {}
    if not outfit_ids:
        return results

    base_url = "https://thumbnails.roblox.com/v1/users/outfits"
    failed_requests = 0
    max_failures = 3

    for i in range(0, len(outfit_ids), THUMB_CHUNK):
        if failed_requests >= max_failures:
            logger.warning("Too many thumbnail request failures, stopping")
            break
            
        chunk = outfit_ids[i:i + THUMB_CHUNK]
        ids_csv = ",".join(str(x) for x in chunk)
        url = f"{base_url}?userOutfitIds={ids_csv}&size={size}&format=Png&isCircular=false"
        
        response = make_request_with_retry(url, headers=HEADERS)
        if not response:
            failed_requests += 1
            continue
        
        try:
            data = response.json().get("data", [])
            for item in data:
                target_id = item.get("targetId")
                if target_id:
                    results[target_id] = {
                        "state": item.get("state"),
                        "imageUrl": item.get("imageUrl"),
                        "version": item.get("version")
                    }
            
            time.sleep(0.15)
            
        except Exception as e:
            logger.error(f"Error parsing thumbnails chunk {i}: {str(e)}")
            failed_requests += 1
            continue

    logger.info(f"Successfully fetched {len(results)} thumbnails")
    return results

def add_to_search_history(username, user_info, outfit_count):
    """Add search to history for analytics"""
    timestamp = datetime.now()
    client_ip = get_client_ip()
    
    if 'recent_searches' not in session:
        session['recent_searches'] = []
    
    # Add to session history (limited to last 5)
    search_entry = {
        'username': username,
        'timestamp': timestamp.isoformat(),
        'outfit_count': outfit_count
    }
    
    session['recent_searches'].insert(0, search_entry)
    session['recent_searches'] = session['recent_searches'][:5]
    
    # Global search history for analytics
    hour_key = timestamp.strftime('%Y-%m-%d-%H')
    if hour_key not in search_history:
        search_history[hour_key] = []
    
    search_history[hour_key].append({
        'username': username,
        'ip': hashlib.md5(client_ip.encode()).hexdigest()[:8],  # Anonymous IP hash
        'timestamp': timestamp.isoformat(),
        'outfit_count': outfit_count
    })

# ---- Flask Routes ----
@app.route("/", methods=["GET", "POST"])
def index():
    """Main page with enhanced functionality"""
    if request.method == "GET":
        recent_searches = session.get('recent_searches', [])
        return render_template("index.html", recent_searches=recent_searches)
    
    # POST request handling
    username = request.form.get("username", "").strip()
    
    # Validation
    if not username:
        return render_template("index.html", 
                             message="⚠️ Please enter a username.",
                             message_type="warning")
    
    if len(username) > 20 or len(username) < 3:
        return render_template("index.html", 
                             message="⚠️ Username must be between 3-20 characters.",
                             message_type="warning",
                             username=username)
    
    # Rate limiting
    if not rate_limit_check():
        return render_template("index.html", 
                             message="⚠️ Too many searches this hour. Please try again later.",
                             message_type="error",
                             username=username)
    
    # Check cache first
    cached_result = get_cached_data(username)
    if cached_result:
        return render_template("index.html", 
                             username=cached_result['username'],
                             user_info=cached_result['user_info'],
                             outfits=cached_result['display_outfits'],
                             message="✨ Results loaded from cache (faster!).",
                             message_type="info",
                             recent_searches=session.get('recent_searches', []))
    
    increment_rate_limit()
    
    # Fetch user information
    user_info = get_user_info(username)
    if not user_info:
        return render_template("index.html",
                             message=f"❌ Could not find user '{username}'. Please check the spelling.",
                             message_type="error",
                             username=username,
                             recent_searches=session.get('recent_searches', []))
    
    # Fetch outfits
    raw_outfits = fetch_all_outfits_enhanced(user_info["id"])
    if not raw_outfits:
        result_data = {
            'username': user_info["username"],
            'user_info': user_info,
            'display_outfits': []
        }
        set_cached_data(username, result_data)
        add_to_search_history(username, user_info, 0)
        
        return render_template("index.html",
                             username=user_info["username"],
                             user_info=user_info,
                             outfits=[],
                             message=f"ℹ️ User '{user_info['username']}' has no public outfits or creations.",
                             message_type="info",
                             recent_searches=session.get('recent_searches', []))
    
    # Fetch thumbnails
    outfit_ids = [o.get("id") for o in raw_outfits if o.get("id") is not None]
    thumbs = fetch_outfit_thumbnails_enhanced(outfit_ids)
    
    # Build display data
    display_outfits = []
    completed_count = 0
    
    for outfit in raw_outfits:
        outfit_id = outfit.get("id")
        name = outfit.get("name") or "(Unnamed Outfit)"
        thumb_data = thumbs.get(outfit_id, {})
        state = thumb_data.get("state", "Unknown")
        image_url = thumb_data.get("imageUrl")
        
        # Only use image if thumbnail generation completed
        img_src = image_url if (state == "Completed" and image_url) else None
        if img_src:
            completed_count += 1
        
        display_outfits.append({
            "id": outfit_id,
            "name": name,
            "state": state,
            "img": img_src,
            "created": outfit.get("created"),
            "updated": outfit.get("updated")
        })
    
    # Cache the results
    result_data = {
        'username': user_info["username"],
        'user_info': user_info,
        'display_outfits': display_outfits
    }
    set_cached_data(username, result_data)
    add_to_search_history(username, user_info, len(display_outfits))
    
    success_message = f"✅ Found {len(display_outfits)} outfits ({completed_count} with thumbnails)."
    
    return render_template("index.html",
                         username=user_info["username"],
                         user_info=user_info,
                         outfits=display_outfits,
                         message=success_message,
                         message_type="success",
                         recent_searches=session.get('recent_searches', []))

@app.route("/api/stats")
def api_stats():
    """API endpoint for application statistics"""
    total_searches = sum(len(searches) for searches in search_history.values())
    active_cache_entries = len(user_cache)
    
    return jsonify({
        "total_searches": total_searches,
        "cached_users": active_cache_entries,
        "uptime": "Unknown",  # Would need startup time tracking
        "rate_limits_active": len(rate_limit_cache)
    })

@app.route("/clear_history")
def clear_history():
    """Clear user's search history"""
    session.pop('recent_searches', None)
    return redirect(url_for('index'))

@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors gracefully"""
    return render_template("index.html", 
                         message="❌ An internal error occurred. Please try again later.",
                         message_type="error"), 500

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return redirect(url_for('index'))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)