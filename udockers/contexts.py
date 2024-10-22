import requests
from django.core.cache import cache
from udockers.settings import VERSION_STR

def version(request):
    return {'version': VERSION_STR}

# 检查GitHub中版本
def get_latest_github_version(owner, repo):
    url = f'https://api.github.com/repos/{owner}/{repo}/tags'
    try:
        response = requests.get(url, timeout=10)  # 加入超时设置
        if response.status_code == 200:
            tags = response.json()
            if tags:
                latest_tag = tags[0]['name']
                if latest_tag.startswith('v'):
                    latest_tag = latest_tag[1:]
                return latest_tag
    except requests.exceptions.RequestException as e:
        print(f"Error fetching version from GitHub: {e}")
    return None

def latest_version(request):
    cache_key = 'latest_github_version'
    latest_version = cache.get(cache_key)
    if not latest_version:
        latest_version = get_latest_github_version('llody55', 'udocker')
        if latest_version:
            cache.set(cache_key, latest_version, 3600) 
    show_notification = not request.session.get('update_notified', False)
    return {'latest_version': latest_version,'show_notification':show_notification}