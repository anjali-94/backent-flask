import requests
import hashlib
import random
import time
from urllib.parse import quote
from cachetools import TTLCache
import logging
from dotenv import load_dotenv
import os

load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# Google Custom Search API credentials from environment
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
CX = os.getenv("CX")

# Cache to store search results (TTL: 1 hour)
cache = TTLCache(maxsize=1000, ttl=3600)

# Flag to disable real API calls after hitting rate limit
disable_real_fetch = False

def check_plagiarism(text):
    global disable_real_fetch
    sentences = [s.strip() for s in text.split('.') if s.strip()]
    total_sentences = len(sentences)
    plagiarized_count = 0
    results = []

    # Batch sentences to reduce API calls (max 5 sentences per query)
    batch_size = 2
    for i in range(0, total_sentences, batch_size):
        batch = sentences[i:i + batch_size]
        batch_query = " ".join(batch)
        batch_results = search_google(batch_query, batch)

        for sentence, is_plagiarized, source in batch_results:
            color = "red" if is_plagiarized else "green"
            results.append({
                "sentence": sentence,
                "color": color,
                "is_plagiarized": is_plagiarized,
                "source": source if is_plagiarized else None
            })
            if is_plagiarized:
                plagiarized_count += 1

        # Avoid rate limiting
        time.sleep(1)

    plagiarism_percentage = (plagiarized_count / total_sentences * 100) if total_sentences > 0 else 0
    return {
        "plagiarism_percentage": round(plagiarism_percentage, 2),
        "results": results
    }

def search_google(query, sentences):
    global disable_real_fetch

    # Check cache first
    cache_key = hashlib.md5(query.encode()).hexdigest()
    if cache_key in cache:
        logger.info(f"Cache hit for query: {query}")
        return cache[cache_key]

    if disable_real_fetch:
        return [pseudo_plagiarism_estimate(s) for s in sentences]

    search_url = f"https://www.googleapis.com/customsearch/v1?q={quote(query)}&key={GOOGLE_API_KEY}&cx={CX}"
    retries = 3
    backoff_factor = 2

    for attempt in range(retries):
        try:
            response = requests.get(search_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                results = []
                if 'items' in data and len(data['items']) > 0:
                    for sentence in sentences:
                        is_plagiarized = False
                        source = None
                        for item in data['items']:
                            if 'snippet' in item and sentence.lower() in item['snippet'].lower():
                                is_plagiarized = True
                                source = item.get('link', 'Unknown source')
                                logger.info(f"Plagiarism detected for: {sentence} (Source: {source})")
                                break
                        results.append((sentence, is_plagiarized, source))
                else:
                    results = [(s, False, None) for s in sentences]
                    logger.info(f"No results found for query: {query}")
                cache[cache_key] = results
                return results
            elif response.status_code == 429:
                logger.warning(f"Rate limit hit. Attempt {attempt + 1}/{retries}. Waiting...")
                time.sleep(backoff_factor ** attempt)
            else:
                logger.error(f"API returned status {response.status_code}. Switching to pseudo mode.")
                disable_real_fetch = True
                return [pseudo_plagiarism_estimate(s) for s in sentences]
        except Exception as e:
            logger.error(f"Exception occurred: {e}. Attempt {attempt + 1}/{retries}.")
            if attempt == retries - 1:
                logger.error("Max retries reached. Switching to pseudo mode.")
                disable_real_fetch = True
                return [pseudo_plagiarism_estimate(s) for s in sentences]
            time.sleep(backoff_factor ** attempt)

    return [pseudo_plagiarism_estimate(s) for s in sentences]

def pseudo_plagiarism_estimate(sentence):
    hash_val = int(hashlib.md5(sentence.encode()).hexdigest(), 16)
    probability = (hash_val % 100) / 100.0
    logger.info(f"Simulated plagiarism check for '{sentence}': Probability {probability}")
    return (sentence, probability > 0.5, None)








