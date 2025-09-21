import os
os.environ['FLASK_ENV'] = 'development'
from app import get_user_info, fetch_user_badges

u = get_user_info('builderman')
print('User:', u)
if u:
    b = fetch_user_badges(u['id'], limit=20)
    print('Badges count:', len(b))
    for i,x in enumerate(b[:20]):
        print(i+1, x.get('id'), x.get('name'), 'place=', x.get('place'), 'game_name=', x.get('game_name'))
