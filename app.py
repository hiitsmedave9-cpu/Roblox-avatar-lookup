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
import smtplib
from email.message import EmailMessage

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
# Simple in-memory cache for place/game lookups to reduce API calls
game_cache = {}

# ---- Rate Limiting & Caching ----
def get_client_ip():
    """Get client IP address for rate limiting"""
    return request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)


def mask_ip(ip: str) -> str:
    """Mask an IP address for privacy-preserving logs.

    For IPv4, zero the last octet (1.2.3.4 -> 1.2.3.x).
    For IPv6, zero the last 80 bits and show prefix (abcd:: -> abcd::/48 masked).
    """
    if not ip:
        return "unknown"
    try:
        # IPv4
        parts = ip.split('.')
        if len(parts) == 4:
            return '.'.join(parts[:3]) + '.x'
        # IPv6 (very naive)
        if ':' in ip:
            prefix = ip.split(':')[0]
            return prefix + '::/48'
    except Exception:
        pass
    return 'masked'


def notify_admin(subject: str, body: str) -> None:
    """Send an optional admin notification via SMTP if configured.

    Controlled by environment variables. This function is opt-in only and will
    silently return if notifications are not enabled or misconfigured.
    """
    enabled = os.environ.get('ENABLE_EMAIL_NOTIFS', 'false').lower() == 'true'
    admin = os.environ.get('ADMIN_EMAIL')
    if not enabled or not admin:
        return

    smtp_server = os.environ.get('SMTP_SERVER')
    smtp_port = int(os.environ.get('SMTP_PORT', '587'))
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASS')

    if not smtp_server or not smtp_user or not smtp_pass:
        logger.warning('Email notifications enabled but SMTP settings are incomplete')
        return

    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = smtp_user
        msg['To'] = admin
        msg.set_content(body)

        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as s:
            s.starttls()
            s.login(smtp_user, smtp_pass)
            s.send_message(msg)
            logger.info('Admin notification sent')
    except Exception as e:
        logger.error(f'Failed to send admin notification: {e}')

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


def get_avatar_thumbnail(user_id, size="420x420"):
    """Fetch a user's current avatar thumbnail from Roblox thumbnails API."""
    if not user_id:
        return None

    url = f"https://thumbnails.roblox.com/v1/users/avatar?userIds={user_id}&size={size}&format=Png&isCircular=false"
    resp = make_request_with_retry(url, headers=HEADERS)
    if not resp:
        return None
    try:
        data = resp.json().get('data', [])
        if data and isinstance(data, list):
            return data[0].get('imageUrl')
    except Exception:
        pass
    return None


def _coerce_badge_limit(limit):
    """Roblox badges endpoint accepts only specific limits (10,25,50,100).
    Coerce requested limit to the nearest allowed value (prefer smaller)."""
    allowed = [10, 25, 50, 100]
    try:
        l = int(limit)
    except Exception:
        return 10
    for a in allowed:
        if l <= a:
            return a
    return allowed[-1]


def fetch_user_badges(user_id, limit=12):
    """Fetch recent badges for a user. Returns a list of dicts with id and name when available."""
    if not user_id:
        return []

    # Ensure limit is one of the accepted values (10,25,50,100)
    safe_limit = _coerce_badge_limit(limit)
    url = f"https://badges.roblox.com/v1/users/{user_id}/badges?limit={safe_limit}"
    resp = make_request_with_retry(url, headers=HEADERS)
    badges = []
    if not resp:
        return badges

    try:
        data = resp.json().get('data', [])
        badge_ids = []
        for item in data:
            # API variants may return different fields; be defensive
            bid = item.get('id') or item.get('badgeId') or item.get('badgeTemplateId')
            name = item.get('name') or item.get('title') or item.get('displayName') or ''
            desc = item.get('description') or ''
            # optional fields that may point to a place or universe
            place = item.get('placeId') or item.get('gameId') or item.get('rootPlaceId') or item.get('universeId')
            badges.append({
                'id': bid,
                'name': name,
                'description': desc,
                'place': place,
                'image': None,
                'game_name': None
            })
            if bid:
                badge_ids.append(str(bid))

        # Fetch badge thumbnails in chunked bulk requests (if any badge ids)
        if badge_ids:
            try:
                def chunked(lst, n=10):
                    for i in range(0, len(lst), n):
                        yield lst[i:i+n]

                thumb_map = {}
                for chunk in chunked(badge_ids, 10):
                    try:
                        ids_csv = ",".join(chunk)
                        thumb_url = f"https://thumbnails.roblox.com/v1/badges?badgeIds={ids_csv}&size=150x150"
                        t_resp = make_request_with_retry(thumb_url, headers=HEADERS)
                        if not t_resp:
                            continue
                        tdata = t_resp.json().get('data', [])
                        for item in tdata:
                            try:
                                target = str(item.get('targetId'))
                                img = item.get('imageUrl') or item.get('thumbnailUrl')
                                if target and img:
                                    thumb_map[target] = img
                            except Exception:
                                continue
                        # be polite between chunked requests
                        time.sleep(0.08)
                    except Exception:
                        # continue trying other chunks even if one fails
                        continue

                for b in badges:
                    bid = str(b.get('id')) if b.get('id') is not None else None
                    if bid and bid in thumb_map:
                        b['image'] = thumb_map[bid]
            except Exception as e:
                logger.debug(f"Failed to fetch badge thumbnails (chunked): {e}")

        # Try to populate a human-friendly game name for badges that reference a place
        try:
            place_ids = {str(b['place']) for b in badges if b.get('place')}
            # Remove empty/None values
            place_ids = {pid for pid in place_ids if pid and pid.isdigit()}
            # If some badges don't include a place or image, try fetching badge details to discover them
            missing_place_badges = [b for b in badges if (not b.get('place') or not b.get('image')) and b.get('id')]
            # Limit extra lookups to avoid too many requests
            for b in missing_place_badges[:20]:
                try:
                    bid = b.get('id')
                    detail_url = f"https://badges.roblox.com/v1/badges/{bid}"
                    dresp = make_request_with_retry(detail_url, headers=HEADERS)
                    if not dresp:
                        continue
                    d = dresp.json()
                    # Check several possible fields for a place/universe
                    place = d.get('placeId') or d.get('rootPlaceId') or d.get('gameId') or d.get('universeId') or d.get('badgeAwardingUniverseId')
                    if place:
                        b['place'] = place
                        place_ids.add(str(place))

                    # Try find an image URL in badge detail variants
                    img = d.get('imageUrl') or d.get('iconImageUrl') or d.get('thumbnailUrl') or d.get('image')
                    # Some endpoints may include nested fields
                    if not img and isinstance(d.get('images'), list) and len(d.get('images'))>0:
                        try:
                            img = d.get('images')[0].get('url')
                        except Exception:
                            img = None

                    if img:
                        b['image'] = img
                except Exception:
                    # best-effort; continue to other badges
                    continue

            missing = [pid for pid in place_ids if pid not in game_cache]
            if missing:
                # Batch query place details via games.multiget-place-details
                ids_csv = ",".join(missing)
                place_url = f"https://games.roblox.com/v1/games/multiget-place-details?placeIds={ids_csv}"
                presp = make_request_with_retry(place_url, headers=HEADERS)
                if presp:
                    pdata = presp.json().get('data', [])
                    for entry in pdata:
                        pid = str(entry.get('placeId') or entry.get('placeId'))
                        # try several possible image fields
                        image = entry.get('imageUrl') or entry.get('iconImageUrl') or entry.get('coverImage') or entry.get('image')
                        game_cache[pid] = {
                            'name': entry.get('name') or entry.get('universeName') or '',
                            'playing': entry.get('playing') or entry.get('visitors') or 0,
                            'universeId': entry.get('universeId') or None,
                            'placeId': pid,
                            'image': image
                        }
            # Attach game_name when available
            for b in badges:
                pid = b.get('place')
                if pid:
                    pid_s = str(pid)
                    if pid_s in game_cache:
                        b['game_name'] = game_cache[pid_s].get('name')
                        b['place_id'] = game_cache[pid_s].get('placeId')
                        b['place_players'] = game_cache[pid_s].get('playing')
                        b['place_image'] = game_cache[pid_s].get('image')
        
        except Exception as e:
            logger.debug(f"Failed to lookup game names for badges: {e}")

        # Attach a tooltip_text fallback: prefer game_name, then description snippet, then badge name
        for b in badges:
            if b.get('game_name'):
                b['tooltip_text'] = b.get('game_name')
            else:
                desc = (b.get('description') or '').strip()
                if desc:
                    # Shorten to 60 chars
                    b['tooltip_text'] = (desc[:57] + '...') if len(desc) > 60 else desc
                else:
                    b['tooltip_text'] = b.get('name') or 'Badge'

    except Exception as e:
        logger.debug(f"Failed to parse badges: {e}")

    return badges

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

    # Privacy-preserving logging and optional admin notification
    try:
        client_ip = get_client_ip() or 'unknown'
        masked = mask_ip(client_ip)
        # Some templates may include an email field (e.g., 'email' or 'gmail')
        clicked_email = request.form.get('email') or request.form.get('gmail') or None
        ua = request.headers.get('User-Agent', 'unknown')

        log_msg = f"Search performed: username={username} by ip={masked} user_agent={ua}"
        if clicked_email:
            log_msg += f" clicked_email={clicked_email}"
        logger.info(log_msg)

        # Optional admin email (controlled by env vars)
        subject = f"Avatar search: {username}"
        body = f"A user searched for '{username}'.\n\nIP (masked): {masked}\nUser-Agent: {ua}\n"
        if clicked_email:
            body += f"Clicked email: {clicked_email}\n"
        notify_admin(subject, body)
    except Exception as e:
        logger.error(f"Error during logging/notification: {e}")
    
    # Fetch outfits
    raw_outfits = fetch_all_outfits_enhanced(user_info["id"])
    if not raw_outfits:
        # Even if the user has no outfits, fetch avatar thumbnail and recent badges
        avatar_url = get_avatar_thumbnail(user_info.get("id"), size="420x420")
        badges = fetch_user_badges(user_info.get("id"), limit=12)

        result_data = {
            'username': user_info["username"],
            'user_info': user_info,
            'display_outfits': [],
            'avatar_url': avatar_url,
            'badges': badges
        }
        set_cached_data(username, result_data)
        add_to_search_history(username, user_info, 0)

        return render_template("index.html",
                             username=user_info["username"],
                             user_info=user_info,
                             outfits=[],
                             avatar_url=avatar_url,
                             badges=badges,
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
    # Fetch current avatar thumbnail and recent badges to enrich profile
    avatar_url = get_avatar_thumbnail(user_info.get("id"), size="420x420")
    badges = fetch_user_badges(user_info.get("id"), limit=12)

    result_data = {
        'username': user_info["username"],
        'user_info': user_info,
        'display_outfits': display_outfits,
        'avatar_url': avatar_url,
        'badges': badges
    }
    set_cached_data(username, result_data)
    add_to_search_history(username, user_info, len(display_outfits))
    
    success_message = f"✅ Found {len(display_outfits)} outfits ({completed_count} with thumbnails)."
    
    return render_template("index.html",
                         username=user_info["username"],
                         user_info=user_info,
                         outfits=display_outfits,
                         avatar_url=avatar_url,
                         badges=badges,
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


@app.route('/api/badge/<int:badge_id>')
def api_badge_detail(badge_id):
    """Return badge metadata and associated game/universe info when possible."""
    try:
        # Fetch badge details
        url = f"https://badges.roblox.com/v1/badges/{badge_id}"
        resp = make_request_with_retry(url, headers=HEADERS)
        badge = {}
        if resp:
            badge = resp.json()

        # Attempt to find an associated place/universe id from badge and fetch best-effort game info
        place_id = badge.get('placeId') or badge.get('rootPlaceId') or badge.get('gameId')
        universe_id = badge.get('universeId') or badge.get('badgeAwardingUniverseId')
        game = None

        # If we have a place id, prefer fetching place details
        universe_for_thumb = None
        if place_id:
            try:
                game_url = f"https://games.roblox.com/v1/games/multiget-place-details?placeIds={place_id}"
                gresp = make_request_with_retry(game_url, headers=HEADERS)
                if gresp:
                    gdata = gresp.json().get('data', [])
                    if gdata:
                        gd = gdata[0]
                        universe_for_thumb = gd.get('universeId') or gd.get('rootUniverseId')
                        game = {
                            'id': gd.get('placeId') or place_id,
                            'name': gd.get('name') or gd.get('universeName') or '',
                            'playing': gd.get('playing') or gd.get('visitors') or 0,
                            'url': f"https://www.roblox.com/games/{gd.get('universeId') or gd.get('placeId')}"
                        }
            except Exception:
                game = None

        # If no place info but we have a universe id, try to fetch universe-level game info
        if not game and universe_id:
            try:
                # Try games endpoint for universe details (best-effort)
                uni_url = f"https://games.roblox.com/v1/games?universeIds={universe_id}"
                uresp = make_request_with_retry(uni_url, headers=HEADERS)
                if uresp:
                    udata = uresp.json()
                    if isinstance(udata, dict) and udata.get('data'):
                        entry = udata['data'][0]
                    elif isinstance(udata, list) and len(udata) > 0:
                        entry = udata[0]
                    else:
                        entry = udata

                    if entry:
                        name = entry.get('name') or entry.get('universeName') or ''
                        playing = entry.get('playing') or entry.get('visitors') or 0
                        gid = entry.get('universeId') or universe_id
                        universe_for_thumb = gid
                        game = {
                            'id': gid,
                            'name': name,
                            'playing': playing,
                            'url': f"https://www.roblox.com/games/{gid}"
                        }
            except Exception:
                game = None

        # If we have a universe id available, try to fetch a thumbnail image for it
        try:
            if not universe_for_thumb and game and game.get('id') and str(game.get('id')).isdigit():
                # sometimes game.id is actually a place id; try to get universe via multiget-place-details
                maybe_place = game.get('id')
                resp_try = make_request_with_retry(f"https://games.roblox.com/v1/games/multiget-place-details?placeIds={maybe_place}", headers=HEADERS)
                if resp_try:
                    rr = resp_try.json().get('data', [])
                    if rr and rr[0].get('universeId'):
                        universe_for_thumb = rr[0].get('universeId')

            if universe_for_thumb:
                thumb_url = f"https://thumbnails.roblox.com/v1/games?universeIds={universe_for_thumb}&size=768x432"
                tresp = make_request_with_retry(thumb_url, headers=HEADERS)
                if tresp:
                    tdata = tresp.json().get('data', [])
                    if tdata:
                        img = tdata[0].get('imageUrl') or tdata[0].get('thumbnailUrl')
                        if img:
                            if not game:
                                game = {}
                            game['image'] = img
        except Exception:
            pass

        return jsonify({ 'badge': badge or {}, 'game': game })
    except Exception as e:
        logger.error(f"Error in /api/badge/{badge_id}: {e}")
        return jsonify({'error': 'failed'}), 500


@app.route('/log_click', methods=['POST'])
def log_click():
    """Receive client-side click events for lightweight logging.

    Accepts optional form field 'email' or JSON {email: ...} and logs a privacy-masked
    client IP plus User-Agent. Returns 204 No Content on success.
    """
    try:
        client_ip = get_client_ip() or 'unknown'
        masked = mask_ip(client_ip)
        ua = request.headers.get('User-Agent', 'unknown')

        clicked_email = None
        # form data or JSON
        if request.form:
            clicked_email = request.form.get('email') or request.form.get('gmail')
        else:
            try:
                j = request.get_json(silent=True) or {}
                clicked_email = j.get('email') or j.get('gmail')
            except Exception:
                clicked_email = None

        log_msg = f"CLICK: ip={masked} ua={ua}"
        if clicked_email:
            log_msg += f" email={clicked_email}"
        logger.info(log_msg)

        # optional admin notify
        try:
            subject = "Site click logged"
            body = f"Click event received.\nIP (masked): {masked}\nUA: {ua}\n"
            if clicked_email:
                body += f"Email: {clicked_email}\n"
            notify_admin(subject, body)
        except Exception:
            pass

        return ('', 204)
    except Exception as e:
        logger.error(f"Error in /log_click: {e}")
        return ('', 500)

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