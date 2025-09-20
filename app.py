from flask import Flask, render_template, request
import requests
import time
from requests.exceptions import RequestException

app = Flask(__name__)

# ---- Configuration ----
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT; Win64; x64)",
    "Accept": "application/json"
}
OUTFITS_PER_PAGE = 50   # how many outfits we request per page
THUMB_CHUNK = 20        # how many outfit ids per thumbnail batch
REQUEST_TIMEOUT = 10    # seconds
MAX_PAGES = 10          # safety cap for pagination

# ---- Helper functions ----

def get_user_id(username: str):
    """Resolve a Roblox username to numeric userId using users.roblox.com."""
    if not username:
        return None
    url = "https://users.roblox.com/v1/usernames/users"
    payload = {"usernames": [username], "excludeBannedUsers": False}
    try:
        resp = requests.post(url, json=payload, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        print(f"[get_user_id] status={resp.status_code}")
        # print small debug snippet on success/fail
        if resp.status_code != 200:
            print("[get_user_id] response:", resp.text[:300])
            return None
        data = resp.json()
        if data.get("data") and len(data["data"]) > 0:
            return data["data"][0].get("id")
    except RequestException as e:
        print("[get_user_id] request failed:", e)
    return None


def fetch_all_outfits(user_id: int, items_per_page=OUTFITS_PER_PAGE, max_pages=MAX_PAGES):
    """
    Get all outfits (saved outfits / creations) for a user, paging through results.
    Returns the raw list of outfit dicts (as returned by avatar.roblox.com).
    """
    if not user_id:
        return []
    outfits = []
    page = 1
    while page <= max_pages:
        url = f"https://avatar.roblox.com/v1/users/{user_id}/outfits"
        params = {"itemsPerPage": items_per_page, "page": page}
        try:
            resp = requests.get(url, headers=HEADERS, params=params, timeout=REQUEST_TIMEOUT)
            print(f"[fetch_all_outfits] page={page} status={resp.status_code}")
            if resp.status_code != 200:
                print("[fetch_all_outfits] response:", resp.text[:400])
                break
            data = resp.json()
            page_items = data.get("data", [])
            if not page_items:
                break
            outfits.extend(page_items)
            # if last page is smaller, break early
            if len(page_items) < items_per_page:
                break
            page += 1
            time.sleep(0.15)  # small polite delay
        except RequestException as e:
            print("[fetch_all_outfits] request failed:", e)
            break
    print(f"[fetch_all_outfits] total_outfits_collected={len(outfits)}")
    return outfits


def fetch_outfit_thumbnails(outfit_ids, size="420x420"):
    """
    Batch-request outfit thumbnails.
    Returns dict mapping outfit_id -> {"state": state, "imageUrl": url or None}
    """
    results = {}
    if not outfit_ids:
        return results

    # thumbnails.roblox.com endpoint (user outfits)
    base = "https://thumbnails.roblox.com/v1/users/outfits"

    # chunk the list to avoid overly long requests
    for i in range(0, len(outfit_ids), THUMB_CHUNK):
        chunk = outfit_ids[i:i + THUMB_CHUNK]
        ids_csv = ",".join(str(x) for x in chunk)
        url = f"{base}?userOutfitIds={ids_csv}&size={size}&format=Png&isCircular=false"
        try:
            resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
            print(f"[fetch_outfit_thumbnails] chunk_start={i} status={resp.status_code}")
            if resp.status_code != 200:
                print("[fetch_outfit_thumbnails] bad response:", resp.text[:400])
                time.sleep(0.2)
                continue
            data = resp.json().get("data", [])
            for item in data:
                target = item.get("targetId")
                results[target] = {
                    "state": item.get("state"),
                    "imageUrl": item.get("imageUrl")
                }
            time.sleep(0.12)
        except RequestException as e:
            print("[fetch_outfit_thumbnails] request failed:", e)
            time.sleep(0.25)
            continue
    return results


# ---- Flask route ----

@app.route("/", methods=["GET", "POST"])
def index():
    username = None
    display_outfits = []
    message = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if not username:
            message = "Please enter a username."
            return render_template("index.html", username=username, outfits=display_outfits, message=message)

        # 1) Resolve username -> user id
        user_id = get_user_id(username)
        if not user_id:
            message = f"❌ Could not find user '{username}'. Make sure you typed it exactly."
            return render_template("index.html", username=username, outfits=display_outfits, message=message)

        # 2) Get outfits (saved outfits + creations)
        raw_outfits = fetch_all_outfits(user_id)
        if not raw_outfits:
            message = f"ℹ️ User '{username}' has no saved outfits / creations (or the API returned none)."
            return render_template("index.html", username=username, outfits=display_outfits, message=message)

        # 3) Batch-fetch thumbnails
        outfit_ids = [o.get("id") for o in raw_outfits if o.get("id") is not None]
        thumbs = fetch_outfit_thumbnails(outfit_ids)

        # 4) Build display list with state and image (only when Completed)
        for o in raw_outfits:
            oid = o.get("id")
            name = o.get("name") or "(no name)"
            thumb = thumbs.get(oid, {})
            state = thumb.get("state") or "Unknown"
            imageUrl = thumb.get("imageUrl")
            # Only use imageUrl if the thumbnail generation is Completed
            img_src = imageUrl if (state == "Completed" and imageUrl) else None
            display_outfits.append({
                "id": oid,
                "name": name,
                "state": state,
                "img": img_src
            })

    return render_template("index.html", username=username, outfits=display_outfits, message=message)


if __name__ == "__main__":
    # debug=True prints stack traces to console and auto-reloads on change
    app.run(debug=True)
