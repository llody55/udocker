from udockers.settings import VERSION_STR

def version(request):
    return {'version': VERSION_STR}