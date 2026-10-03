"""Zero-code protection: point the OpenAI client at NEOS Guard. Run: python server.py"""
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8080/guard/proxy/v1", api_key="YOUR_OPENAI_KEY")
# every call is now auto-guarded (input injection blocked + output leaks masked)
resp = client.chat.completions.create(
    model="gpt-4o-mini", messages=[{"role": "user", "content": "Hello!"}])
print(resp.choices[0].message.content)
