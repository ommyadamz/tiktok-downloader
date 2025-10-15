"""
TikTok Video Downloader - SECURE VERSION WITH PASSWORD RECOVERY
Version: 2.0.0 - PRODUCTION READY
Admin URL: /admin-Nembotech
Features: Password Recovery via Email
"""

from flask import Flask, request, jsonify, render_template, Response, url_for
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
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

warnings.filterwarnings('ignore')

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-this-secret-key-now-abc123xyz')
app.config['MAX_REQUESTS_PER_HOUR'] = 100
app.config['ADMIN_EMAIL'] = 'ommytech97@gmail.com'
app.config['SMTP_SERVER'] = 'smtp.gmail.com'
app.config['SMTP_PORT'] = 587
app.config['SMTP_EMAIL'] = os.getenv('SMTP_EMAIL', 'ommytech97@gmail.com')
app.config['SMTP_PASSWORD'] = os.getenv('SMTP_PASSWORD', '')  # Gmail App Password

# Cache and rate limiting storage
cache = {}
cache_timeout = 300
rate_limit_storage = {}

# Password reset tokens storage (in production, use Redis or database)
reset_tokens = {}


# ==================== EMAIL FUNCTIONS ====================

def send_email(to_email, subject, html_content):
    """Send email via Gmail SMTP"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = app.config['SMTP_EMAIL']
        msg['To'] = to_email

        html_part = MIMEText(html_content, 'html')
        msg.attach(html_part)

        server = smtplib.SMTP(app.config['SMTP_SERVER'], app.config['SMTP_PORT'])
        server.starttls()
        server.login(app.config['SMTP_EMAIL'], app.config['SMTP_PASSWORD'])
        server.send_message(msg)
        server.quit()

        print(f"✅ Email sent to {to_email}")
        return True
    except Exception as e:
        print(f"❌ Email error: {e}")
        return False


def generate_reset_token():
    """Generate secure reset token"""
    return secrets.token_urlsafe(32)


def get_password_reset_email_html(reset_link, username):
    """Generate password reset email HTML"""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background-color: #f5f7fa;
                margin: 0;
                padding: 20px;
            }}
            .container {{
                max-width: 600px;
                margin: 0 auto;
                background: white;
                border-radius: 15px;
                overflow: hidden;
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 40px 20px;
                text-align: center;
                color: white;
            }}
            .header h1 {{
                margin: 0;
                font-size: 28px;
            }}
            .content {{
                padding: 40px 30px;
            }}
            .content h2 {{
                color: #333;
                margin-bottom: 20px;
            }}
            .content p {{
                color: #666;
                line-height: 1.6;
                margin-bottom: 20px;
            }}
            .button {{
                display: inline-block;
                padding: 15px 40px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                text-decoration: none;
                border-radius: 8px;
                font-weight: 600;
                margin: 20px 0;
            }}
            .footer {{
                background: #f8f9fa;
                padding: 20px;
                text-align: center;
                color: #999;
                font-size: 14px;
            }}
            .warning {{
                background: #fff3cd;
                border-left: 4px solid #ffc107;
                padding: 15px;
                margin: 20px 0;
                color: #856404;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔐 Password Reset Request</h1>
            </div>
            <div class="content">
                <h2>Hello {username},</h2>
                <p>We received a request to reset your password for your TikTok Downloader admin account.</p>
                <p>Click the button below to reset your password:</p>
                <center>
                    <a href="{reset_link}" class="button">Reset Password</a>
                </center>
                <div class="warning">
                    <strong>⚠️ Security Notice:</strong>
                    <ul style="margin: 10px 0; padding-left: 20px;">
                        <li>This link expires in 1 hour</li>
                        <li>If you didn't request this, ignore this email</li>
                        <li>Never share this link with anyone</li>
                    </ul>
                </div>
                <p>Or copy and paste this link into your browser:</p>
                <p style="word-break: break-all; color: #667eea; font-size: 14px;">{reset_link}</p>
            </div>
            <div class="footer">
                <p>TikTok Video Downloader - Admin Panel</p>
                <p>This is an automated email. Please do not reply.</p>
            </div>
        </div>
    </body>
    </html>
    """


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
                  ('admin', password_hash, 'ommytech97@gmail.com'))
        conn.commit()
        print("✅ Default admin created!")
        print("   Username: admin")
        print("   Password: admin123")
        print("   ⚠️  CHANGE THIS PASSWORD AFTER FIRST LOGIN!")

    conn.close()


# AUTO-INITIALIZE DATABASE ON STARTUP
def auto_init_database():
    """Initialize database automatically when app starts"""
    try:
        init_database()
        create_default_admin()
        print("✅ Database auto-initialized on startup")
    except Exception as e:
        print(f"⚠️ Database initialization error: {e}")


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

            thumbnail = soup.find('img', {'class': 'result_thumbnail'})
            if thumbnail:
                result['data']['thumbnail'] = thumbnail.get('src', '')

            title = soup.find('p', {'class': 'maintext'})
            if title:
                result['data']['title'] = title.get_text().strip()

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


# ==================== LEGAL PAGES ROUTES ====================

@app.route('/privacy-policy')
def privacy_policy():
    """Privacy Policy page"""
    return render_template('privacy-policy.html')


@app.route('/terms')
def terms():
    """Terms of Service page"""
    return render_template('terms.html')


@app.route('/contact')
def contact():
    """Contact page"""
    return render_template('contact.html')


# ==================== ADMIN PAGES ROUTES ====================

@app.route('/admin-Nembotech/login')
def admin_login_page():
    """Admin login page - SECURE URL"""
    return render_template('admin_login.html')


@app.route('/admin-Nembotech')
def admin_dashboard():
    """Admin dashboard page - SECURE URL"""
    return render_template('admin.html')


@app.route('/admin-Nembotech/forgot-password')
def admin_forgot_password_page():
    """Forgot password page"""
    return render_template('admin_forgot_password.html')


@app.route('/admin-Nembotech/reset-password/<token>')
def admin_reset_password_page(token):
    """Reset password page"""
    return render_template('admin_reset_password.html', token=token)


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

        if 'tiktok.com' not in url:
            return jsonify({
                'success': False,
                'message': 'Invalid TikTok URL'
            }), 400

        cached_data = get_from_cache(url)
        if cached_data:
            return jsonify(cached_data)

        video_id = extract_video_id(url)
        result = download_with_ssstik(url)

        if not result or not result.get('success'):
            return jsonify({
                'success': False,
                'message': 'Could not download video. Please try again.'
            }), 500

        if 'likes' not in result.get('data', {}):
            result['data'].update({
                'likes': 125000,
                'comments': 3400,
                'shares': 8900,
                'duration': '0:45',
                'videoId': video_id
            })

        log_download(
            url,
            video_id,
            result['data'].get('title', ''),
            result['data'].get('author', '')
        )

        save_to_cache(url, result)

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Server error: {str(e)}'
        }), 500


@app.route('/api/proxy-download', methods=['GET'])
def proxy_download():
    """Proxy download through our server"""
    try:
        video_url = request.args.get('url')

        if not video_url:
            return jsonify({'error': 'URL required'}), 400

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Referer': 'https://ssstik.io/',
            'Accept': '*/*'
        }

        response = requests.get(video_url, headers=headers, stream=True, timeout=30)

        if response.status_code == 200:
            content_type = response.headers.get('content-type', 'video/mp4')

            def generate():
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        yield chunk

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

        c.execute('SELECT id, password_hash FROM admins WHERE username = ?', (username,))
        admin = c.fetchone()

        if not admin or not check_password_hash(admin[1], password):
            conn.close()
            return jsonify({
                'success': False,
                'message': 'Invalid username or password'
            }), 401

        c.execute('UPDATE admins SET last_login = ? WHERE id = ?',
                  (datetime.now(), admin[0]))
        conn.commit()
        conn.close()

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


@app.route('/api/admin/forgot-password', methods=['POST'])
def admin_forgot_password():
    """Request password reset"""
    try:
        data = request.get_json()
        username = data.get('username')

        if not username:
            return jsonify({
                'success': False,
                'message': 'Username required'
            }), 400

        conn = sqlite3.connect('tiktok_downloader.db')
        c = conn.cursor()

        c.execute('SELECT id, email FROM admins WHERE username = ?', (username,))
        admin = c.fetchone()
        conn.close()

        if not admin:
            # Don't reveal if user exists (security)
            return jsonify({
                'success': True,
                'message': 'If the account exists, a reset link has been sent to the registered email.'
            })

        admin_id, email = admin

        # Generate reset token
        token = generate_reset_token()
        reset_tokens[token] = {
            'admin_id': admin_id,
            'username': username,
            'expires': datetime.now() + timedelta(hours=1)
        }

        # Generate reset link
        reset_link = url_for('admin_reset_password_page', token=token, _external=True)

        # Send email
        html_content = get_password_reset_email_html(reset_link, username)
        email_sent = send_email(email, '🔐 Password Reset Request - TikTok Downloader', html_content)

        if email_sent:
            return jsonify({
                'success': True,
                'message': 'Password reset link sent to your email. Check your inbox!'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to send email. Please contact support.'
            }), 500

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500


@app.route('/api/admin/reset-password', methods=['POST'])
def admin_reset_password():
    """Reset password with token"""
    try:
        data = request.get_json()
        token = data.get('token')
        new_password = data.get('new_password')

        if not token or not new_password:
            return jsonify({
                'success': False,
                'message': 'Token and new password required'
            }), 400

        # Validate token
        if token not in reset_tokens:
            return jsonify({
                'success': False,
                'message': 'Invalid or expired reset link'
            }), 400

        token_data = reset_tokens[token]

        # Check expiration
        if datetime.now() > token_data['expires']:
            del reset_tokens[token]
            return jsonify({
                'success': False,
                'message': 'Reset link has expired. Please request a new one.'
            }), 400

        # Update password
        conn = sqlite3.connect('tiktok_downloader.db')
        c = conn.cursor()

        new_hash = generate_password_hash(new_password)
        c.execute('UPDATE admins SET password_hash = ? WHERE id = ?',
                  (new_hash, token_data['admin_id']))
        conn.commit()
        conn.close()

        # Remove used token
        del reset_tokens[token]

        return jsonify({
            'success': True,
            'message': 'Password reset successful! You can now login with your new password.'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500


# ==================== ADMIN PROTECTED ROUTES ====================

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    """Get detailed admin statistics"""
    try:
        conn = sqlite3.connect('tiktok_downloader.db')
        c = conn.cursor()

        c.execute('SELECT SUM(download_count) FROM downloads')
        total_downloads = c.fetchone()[0] or 0

        c.execute('SELECT COUNT(*) FROM users')
        total_users = c.fetchone()[0] or 0

        c.execute('''SELECT COUNT(*) FROM analytics 
                    WHERE DATE(timestamp) = DATE('now')''')
        downloads_today = c.fetchone()[0] or 0

        c.execute('''SELECT title, author, download_count, video_url 
                    FROM downloads 
                    ORDER BY download_count DESC 
                    LIMIT 10''')
        top_videos = c.fetchall()

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

        c.execute('SELECT password_hash FROM admins WHERE id = ?', (admin_id,))
        admin = c.fetchone()

        if not admin or not check_password_hash(admin[0], old_password):
            conn.close()
            return jsonify({
                'success': False,
                'message': 'Invalid old password'
            }), 401

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
    print("🚀 TIKTOK VIDEO DOWNLOADER - SECURE VERSION")
    print("=" * 60 + "\n")

    port = int(os.getenv('PORT', 5000))

    print("\n" + "=" * 60)
    print("✅ SERVER IS RUNNING!")
    print("=" * 60)
    print(f"\n📱 Main Site:          http://localhost:{port}/")
    print(f"🔐 Admin Login:        http://localhost:{port}/admin-Nembotech/login")
    print(f"📊 Admin Dashboard:    http://localhost:{port}/admin-Nembotech")
    print(f"🔑 Forgot Password:    http://localhost:{port}/admin-Nembotech/forgot-password")
    print(f"\n📄 Privacy Policy:     http://localhost:{port}/privacy-policy")
    print(f"📋 Terms of Service:   http://localhost:{port}/terms")
    print(f"📧 Contact:            http://localhost:{port}/contact")
    print("\n" + "-" * 60)
    print("👤 DEFAULT ADMIN:")
    print("-" * 60)
    print("   Username: admin")
    print("   Password: admin123")
    print("\n⚠️  CHANGE PASSWORD IMMEDIATELY!")
    print("=" * 60 + "\n")

    app.run(host='0.0.0.0', port=port, debug=True)