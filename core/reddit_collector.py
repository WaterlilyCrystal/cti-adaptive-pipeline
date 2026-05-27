import datetime

import praw
def fetch_reddit(subreddits=["netsec","threatintelligence"], limit=25):
    reddit = praw.Reddit(client_id=cfg.REDDIT_ID,
                         client_secret=cfg.REDDIT_SECRET,
                         user_agent="cti-bot/1.0")
    items = []
    for sub in subreddits:
        for post in reddit.subreddit(sub).hot(limit=limit):
            items.append({"source": f"reddit/{sub}",
                          "title": post.title,
                          "url": post.url,
                          "content": post.selftext,
                          "collected_at": datetime.utcnow().isoformat()})
    return items