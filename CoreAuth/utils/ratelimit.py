from django.core.cache import cache

def activation_code_ratelimit(user):
    
    cache_key = f"activation_attempts:{user.id}"
    attempts = cache.get(cache_key,0)
    
    if attempts >= 5:
        return False
    
    cache.set(cache_key, attempts + 1, timeout=600)
    return True
    