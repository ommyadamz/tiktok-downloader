"""
TikTok Video Downloader - COMPLETE BACKEND WITH PROXY
Version: 1.0.1 FIXED FOR RENDER
Copy this ENTIRE file to: app.py
"""

from flask import Flask, request, jsonify, render_template, Response
from flask_cors import CORS
import requests
import re
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
import hashlib
import time
from bs4 import BeautifulSoup
import os
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import warnings

warnings.filterwarnings('ignore')

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-this-secret-key-now-abc123xyz')
app.config['MAX_REQUESTS_PER_HOUR'] = 100

# Cache and rate limiting storage
cache = {}
cache_timeout = 300  # 5 minutes
rate_limit_storage = {}


# ==================== DATABASE FUNCTIONS ====================

def init_database():
    """Initialize all database tables"""
    conn = sqlite3.connect('tiktok_downloader.db')
    c = conn.cursor()

    # Downloads table
    c.execute('''CREATE TABLE IF NOT EXISTS downloads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        video_url TEXT NOT NULL,
        video_id TEXT,
        title TEXT,
        author TEXT,
        download_count INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_downloaded TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Analytics table
    c.execute('''CREATE TABLE IF NOT EXISTS analytics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT,
        user_agent TEXT,
        endpoint TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_premium BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )''')

    # Admins table
    c.execute('''CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )''')

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")


def create_default_admin():
    """Create default admin account"""
    conn = sqlite3.connect('tiktok_downloader.db')
    c = conn.cursor()

    c.execute('SELECT id FROM admins WHERE username = ?', ('admin',))
    if not c.fetchone():
        password_hash = generate_password_hash('admin123')
        c.execute('''INSERT INTO admins (username, password_hash, email) 
                    VALUES (?, ?, ?)''',
                  ('admin', password_hash, 'admin@tiktokdownloader.com'))
        conn.commit()
        print("✅ Default admin created!")
        print("   Username: admin")
        print("   Password: admin123")
        print("   ⚠️  CHANGE THIS PASSWORD AFTER FIRST LOGIN!")

    conn.close()


# AUTO-INITIALIZE DATABASE ON STARTUP (CRITICAL FOR RENDER!)
def auto_init_database():
    """Initialize database automatically when app starts"""
    try:
        init_database()
        create_default_admin()
        print("✅ Database auto-initialized on startup")
    except Exception as e:
        print(f"⚠️ Database initialization error: {e}")

# Run initialization immediately
auto_init_database()


def log_download(video_url, video_id, title, author):
    """Log download to database"""
    try:
        conn = sqlite3.connect('tiktok_downloader.db')
        c = conn.cursor()

        c.execute('SELECT id, download_count FROM downloads WHERE video_id = ?', (video_id,))
        result = c.fetchone()

        if result:
            new_count = result[1] + 1
            c.execute('''UPDATE downloads 
                        SET download_count = ?, last_downloaded = ? 
                        WHERE id = ?''',
                      (new_count, datetime.now(), result[0]))
        else:
            c.execute('''INSERT INTO downloads 
                        (video_url, video_id, title, author) 
                        VALUES (?, ?, ?, ?)''',
                      (video_url, video_id, title, author))

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database error: {e}")


def log_analytics(ip_address, user_agent, endpoint):
    """Log API usage for analytics"""
    try:
        conn = sqlite3.connect('tiktok_downloader.db')
        c = conn.cursor()
        c.execute('''INSERT INTO analytics (ip_address, user_agent, endpoint) 
                    VALUES (?, ?, ?)''',
                  (ip_address, user_agent, endpoint))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Analytics error: {e}")


# ==================== AUTHENTICATION ====================

def admin_required(f):
    """Decorator to protect admin routes"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')

        if not token:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401

        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.admin_id = payload['admin_id']
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({
                'success': False,
                'message': 'Token expired'
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                'success': False,
                'message': 'Invalid token'
            }), 401

    return decorated_function


# ==================== RATE LIMITING ====================

def rate_limit(max_requests=100, window=3600):
    """Rate limiting decorator"""

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            current_time = time.time()

            if ip not in rate_limit_storage:
                rate_limit_storage[ip] = []

            rate_limit_storage[ip] = [
                req_time for req_time in rate_limit_storage[ip]
                if current_time - req_time < window
            ]

            if len(rate_limit_storage[ip]) >= max_requests:
                return jsonify({
                    'success': False,
                    'message': 'Rate limit exceeded. Try again later.'
                }), 429

            rate_limit_storage[ip].append(current_time)
            return f(*args, **kwargs)

        return wrapped

    return decorator


# ==================== CACHING ====================

def get_cache_key(url):
    """Generate cache key from URL"""
    return hashlib.md5(url.encode()).hexdigest()


def get_from_cache(url):
    """Get data from cache"""
    key = get_cache_key(url)
    if key in cache:
        data, timestamp = cache[key]
        if time.time() - timestamp < cache_timeout:
            return data
        else:
            del cache[key]
    return None


def save_to_cache(url, data):
    """Save data to cache"""
    key = get_cache_key(url)
    cache[key] = (data, time.time())


# ==================== VIDEO PROCESSING ====================

def extract_video_id(url):
    """Extract video ID from TikTok URL"""
    patterns = [
        r'tiktok\.com/@[\w.-]+/video/(\d+)',
        r'tiktok\.com/v/(\d+)',
        r'vm\.tiktok\.com/([\w\d]+)',
        r'vt\.tiktok\.com/([\w\d]+)'
    ]

    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    return None


def download_with_ssstik(url):
    """Download using SSSik method"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': 'https://ssstik.io',
            'Referer': 'https://ssstik.io/en'
        }

        data = {
            'id': url,
            'locale': 'en',
            'tt': 'RFBiZ3Bi'
        }

        response = requests.post(
            'https://ssstik.io/abc?url=dl',
            headers=headers,
            data=data,
            timeout=15
        )

        if response.status_code == 200:
            html = response.text
            soup = BeautifulSoup(html, 'html.parser')

            result = {'success': True, 'data': {}}

            # Find download links
            download_links = soup.find_all('a')
            for link in download_links:
                href = link.get('href', '')
                text = link.get_text().lower()

                if 'without watermark' in text and href:
                    result['data']['videoNoWatermark'] = href
                elif 'with watermark' in text and href:
                    result['data']['videoWithWatermark'] = href
                elif 'audio' in text or 'mp3' in text:
                    result['data']['audio'] = href

            # Extract thumbnail
            thumbnail = soup.find('img', {'class': 'result_thumbnail'})
            if thumbnail:
                result['data']['thumbnail'] = thumbnail.get('src', '')

            # Extract title
            title = soup.find('p', {'class': 'maintext'})
            if title:
                result['data']['title'] = title.get_text().strip()

            # Extract author
            author = soup.find('h2')
            if author:
                result['data']['author'] = author.get_text().strip()

            return result

        return None

    except Exception as e:
        print(f"SSSik error: {e}")
        return None


# ==================== PUBLIC ROUTES ====================

@app.route('/')
def home():
    """Main page - User interface"""
    return render_template('index.html')


@app.route('/admin/login')
def admin_login_page():
    """Admin login page"""
    return render_template('admin_login.html')


@app.route('/admin')
def admin_dashboard():
    """Admin dashboard page"""
    return render_template('admin.html')


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'OK',
        'message': 'API is running',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/download', methods=['POST'])
@rate_limit(max_requests=50, window=3600)
def download_video():
    """Main download endpoint"""
    try:
        # Log analytics
        log_analytics(
            request.remote_addr,
            request.headers.get('User-Agent', ''),
            '/api/download'
        )

        data = request.get_json()

        if not data or 'url' not in data:
            return jsonify({
                'success': False,
                'message': 'URL is required'
            }), 400

        url = data['url'].strip()

        # Validate URL
        if 'tiktok.com' not in url:
            return jsonify({
                'success': False,
                'message': 'Invalid TikTok URL'
            }), 400

        # Check cache first
        cached_data = get_from_cache(url)
        if cached_data:
            return jsonify(cached_data)

        # Extract video ID
        video_id = extract_video_id(url)

        # Try to download
        result = download_with_ssstik(url)

        if not result or not result.get('success'):
            return jsonify({
                'success': False,
                'message': 'Could not download video. Please try again.'
            }), 500

        # Add mock statistics if not present
        if 'likes' not in result.get('data', {}):
            result['data'].update({
                'likes': 125000,
                'comments': 3400,
                'shares': 8900,
                'duration': '0:45',
                'videoId': video_id
            })

        # Log download
        log_download(
            url,
            video_id,
            result['data'].get('title', ''),
            result['data'].get('author', '')
        )

        # Save to cache
        save_to_cache(url, result)

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Server error: {str(e)}'
        }), 500


@app.route('/api/proxy-download', methods=['GET'])
def proxy_download():
    """Proxy download through our server - Downloads show YOUR URL!"""
    try:
        video_url = request.args.get('url')

        if not video_url:
            return jsonify({'error': 'URL required'}), 400

        # Headers to mimic browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Referer': 'https://ssstik.io/',
            'Accept': '*/*'
        }

        # Fetch video from external source
        response = requests.get(video_url, headers=headers, stream=True, timeout=30)

        if response.status_code == 200:
            # Determine content type
            content_type = response.headers.get('content-type', 'video/mp4')

            # Generate chunks
            def generate():
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        yield chunk

            # Return video with proper headers
            return Response(
                generate(),
                mimetype=content_type,
                headers={
                    'Content-Disposition': 'attachment; filename=tiktok_video.mp4',
                    'Content-Type': content_type,
                    'Cache-Control': 'no-cache'
                }
            )
        else:
            return jsonify({'error': 'Failed to fetch video'}), 500

    except Exception as e:
        print(f"Proxy download error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/proxy-image', methods=['GET'])
def proxy_image():
    """Proxy thumbnail images through our server - Fixes CORS issues"""
    try:
        from flask import redirect

        image_url = request.args.get('url')

        if not image_url:
            # Return default placeholder
            return redirect('https://via.placeholder.com/120/667eea/ffffff?text=TikTok')

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Referer': 'https://ssstik.io/',
            'Accept': 'image/*'
        }

        response = requests.get(image_url, headers=headers, timeout=10)

        if response.status_code == 200:
            return Response(
                response.content,
                mimetype=response.headers.get('content-type', 'image/jpeg'),
                headers={
                    'Cache-Control': 'public, max-age=3600',
                    'Access-Control-Allow-Origin': '*'
                }
            )
        else:
            return redirect('https://via.placeholder.com/120/667eea/ffffff?text=TikTok')

    except Exception as e:
        print(f"Image proxy error: {e}")
        return redirect('https://via.placeholder.com/120/667eea/ffffff?text=TikTok')


@app.route('/api/stats', methods=['GET'])
def get_public_stats():
    """Get public statistics"""
    try:
        conn = sqlite3.connect('tiktok_downloader.db')
        c = conn.cursor()

        c.execute('SELECT SUM(download_count) FROM downloads')
        total = c.fetchone()[0] or 0

        conn.close()

        return jsonify({
            'success': True,
            'total_downloads': total
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# ==================== ADMIN AUTHENTICATION ROUTES ====================

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    """Admin login endpoint"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({
                'success': False,
                'message': 'Username and password required'
            }), 400

        conn = sqlite3.connect('tiktok_downloader.db')
        c = conn.cursor()

        # Get admin from database
        c.execute('SELECT id, password_hash FROM admins WHERE username = ?', (username,))
        admin = c.fetchone()

        if not admin or not check_password_hash(admin[1], password):
            conn.close()
            return jsonify({
                'success': False,
                'message': 'Invalid username or password'
            }), 401

        # Update last login
        c.execute('UPDATE admins SET last_login = ? WHERE id = ?',
                  (datetime.now(), admin[0]))
        conn.commit()
        conn.close()

        # Create JWT token
        token = jwt.encode({
            'admin_id': admin[0],
            'username': username,
            'exp': datetime.utcnow() + timedelta(days=30)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({
            'success': True,
            'token': token,
            'message': 'Login successful'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Login error: {str(e)}'
        }), 500


@app.route('/api/admin/verify', methods=['POST'])
def admin_verify():
    """Verify admin token"""
    try:
        token = request.headers.get('Authorization', '').replace('Bearer ', '')

        if not token:
            return jsonify({'success': False, 'message': 'No token'}), 401

        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

        return jsonify({
            'success': True,
            'admin_id': payload['admin_id'],
            'username': payload['username']
        })

    except jwt.ExpiredSignatureError:
        return jsonify({'success': False, 'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'success': False, 'message': 'Invalid token'}), 401


# ==================== ADMIN PROTECTED ROUTES ====================

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    """Get detailed admin statistics"""
    try:
        conn = sqlite3.connect('tiktok_downloader.db')
        c = conn.cursor()

        # Total downloads
        c.execute('SELECT SUM(download_count) FROM downloads')
        total_downloads = c.fetchone()[0] or 0

        # Total users
        c.execute('SELECT COUNT(*) FROM users')
        total_users = c.fetchone()[0] or 0

        # Downloads today
        c.execute('''SELECT COUNT(*) FROM analytics 
                    WHERE DATE(timestamp) = DATE('now')''')
        downloads_today = c.fetchone()[0] or 0

        # Top videos
        c.execute('''SELECT title, author, download_count, video_url 
                    FROM downloads 
                    ORDER BY download_count DESC 
                    LIMIT 10''')
        top_videos = c.fetchall()

        # Recent activity
        c.execute('''SELECT ip_address, endpoint, timestamp 
                    FROM analytics 
                    ORDER BY timestamp DESC 
                    LIMIT 50''')
        recent_activity = c.fetchall()

        conn.close()

        return jsonify({
            'success': True,
            'stats': {
                'total_downloads': total_downloads,
                'total_users': total_users,
                'downloads_today': downloads_today,
                'top_videos': [
                    {
                        'title': v[0] or 'Untitled',
                        'author': v[1] or 'Unknown',
                        'count': v[2],
                        'url': v[3]
                    }
                    for v in top_videos
                ],
                'recent_activity': [
                    {
                        'ip': a[0],
                        'endpoint': a[1],
                        'time': a[2]
                    }
                    for a in recent_activity
                ]
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@app.route('/api/admin/all-downloads', methods=['GET'])
@admin_required
def get_all_downloads():
    """Get all download records"""
    try:
        conn = sqlite3.connect('tiktok_downloader.db')
        c = conn.cursor()

        c.execute('''SELECT id, video_url, video_id, title, author, 
                    download_count, last_downloaded 
                    FROM downloads 
                    ORDER BY last_downloaded DESC 
                    LIMIT 100''')
        downloads = c.fetchall()

        conn.close()

        return jsonify({
            'success': True,
            'downloads': [
                {
                    'id': d[0],
                    'url': d[1],
                    'video_id': d[2],
                    'title': d[3],
                    'author': d[4],
                    'count': d[5],
                    'last_downloaded': d[6]
                }
                for d in downloads
            ]
        })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/admin/analytics', methods=['GET'])
@admin_required
def get_analytics():
    """Get analytics data"""
    try:
        conn = sqlite3.connect('tiktok_downloader.db')
        c = conn.cursor()

        # Week downloads
        c.execute('''SELECT COUNT(*) FROM analytics 
                    WHERE timestamp >= datetime('now', '-7 days')''')
        week_downloads = c.fetchone()[0]

        # Month downloads
        c.execute('''SELECT COUNT(*) FROM analytics 
                    WHERE timestamp >= datetime('now', '-30 days')''')
        month_downloads = c.fetchone()[0]

        # Total unique videos
        c.execute('SELECT COUNT(*) FROM downloads')
        total_videos = c.fetchone()[0]

        # Recent activity
        c.execute('''SELECT ip_address, endpoint, timestamp 
                    FROM analytics 
                    ORDER BY timestamp DESC 
                    LIMIT 20''')
        recent_activity = c.fetchall()

        conn.close()

        return jsonify({
            'success': True,
            'week_downloads': week_downloads,
            'month_downloads': month_downloads,
            'total_videos': total_videos,
            'recent_activity': [
                {
                    'ip': a[0],
                    'endpoint': a[1],
                    'time': a[2]
                }
                for a in recent_activity
            ]
        })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/admin/delete-download/<int:download_id>', methods=['DELETE'])
@admin_required
def delete_download_record(download_id):
    """Delete a download record"""
    try:
        conn = sqlite3.connect('tiktok_downloader.db')
        c = conn.cursor()

        c.execute('DELETE FROM downloads WHERE id = ?', (download_id,))
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Download deleted successfully'
        })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/admin/clear-old-data', methods=['POST'])
@admin_required
def clear_old_data():
    """Clear downloads older than 30 days"""
    try:
        conn = sqlite3.connect('tiktok_downloader.db')
        c = conn.cursor()

        c.execute('''DELETE FROM downloads 
                    WHERE last_downloaded < datetime('now', '-30 days')''')
        deleted = c.rowcount

        c.execute('''DELETE FROM analytics 
                    WHERE timestamp < datetime('now', '-30 days')''')
        deleted += c.rowcount

        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': f'Deleted {deleted} old records'
        })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/clear-cache', methods=['POST'])
@admin_required
def clear_cache_endpoint():
    """Clear server cache"""
    cache.clear()
    return jsonify({
        'success': True,
        'message': 'Cache cleared successfully'
    })


@app.route('/api/admin/change-password', methods=['POST'])
@admin_required
def change_admin_password():
    """Change admin password"""
    try:
        data = request.get_json()
        old_password = data.get('old_password')
        new_password = data.get('new_password')

        if not old_password or not new_password:
            return jsonify({
                'success': False,
                'message': 'Both passwords required'
            }), 400

        admin_id = request.admin_id

        conn = sqlite3.connect('tiktok_downloader.db')
        c = conn.cursor()

        # Verify old password
        c.execute('SELECT password_hash FROM admins WHERE id = ?', (admin_id,))
        admin = c.fetchone()

        if not admin or not check_password_hash(admin[0], old_password):
            conn.close()
            return jsonify({
                'success': False,
                'message': 'Invalid old password'
            }), 401

        # Update password
        new_hash = generate_password_hash(new_password)
        c.execute('UPDATE admins SET password_hash = ? WHERE id = ?',
                  (new_hash, admin_id))
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Password changed successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


# ==================== MAIN ====================

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("🚀 STARTING TIKTOK VIDEO DOWNLOADER WITH PROXY")
    print("=" * 60 + "\n")

    port = int(os.getenv('PORT', 5000))

    print("\n" + "=" * 60)
    print("✅ SERVER IS RUNNING!")
    print("=" * 60)
    print(f"\n📱 Main Site (Users):  http://localhost:{port}/")
    print(f"🔐 Admin Login:        http://localhost:{port}/admin/login")
    print(f"📊 Admin Dashboard:    http://localhost:{port}/admin")
    print(f"💚 Health Check:       http://localhost:{port}/api/health")
    print(f"🔄 Proxy Download:     http://localhost:{port}/api/proxy-download")
    print("\n" + "-" * 60)
    print("👤 DEFAULT ADMIN CREDENTIALS:")
    print("-" * 60)
    print("   Username: admin")
    print("   Password: admin123")
    print("\n⚠️  IMPORTANT: Change password after first login!")
    print("\n✨ NEW: Videos now download through YOUR server!")
    print("   Users will see YOUR URL, not external URLs!")
    print("=" * 60 + "\n")

    app.run(host='0.0.0.0', port=port, debug=True)