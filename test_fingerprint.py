#!/usr/bin/env python3
"""
Quick test for cloud fingerprinting
"""

import asyncio
import aiohttp

async def test_fingerprint():
    """Test fingerprinting logic"""
    
    urls = [
        "https://www.cloudflare.com",
        "https://aws.amazon.com",
        "https://s3.amazonaws.com"
    ]
    
    async with aiohttp.ClientSession() as session:
        for url in urls:
            print(f"\n=== Testing: {url} ===")
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    print(f"Status: {response.status}")
                    print(f"Server: {response.headers.get('Server', 'N/A')}")
                    print("Headers:")
                    for key, value in list(response.headers.items())[:10]:
                        print(f"  {key}: {value[:50]}...")
                    
                    # Check for cloud signatures
                    headers_lower = {k.lower(): v for k, v in response.headers.items()}
                    
                    # CloudFlare
                    if any('cf-' in h for h in headers_lower):
                        print("✓ CloudFlare detected!")
                    
                    # AWS
                    if any('x-amz' in h for h in headers_lower):
                        print("✓ AWS detected!")
                    
                    # Server check
                    server = response.headers.get('Server', '').lower()
                    if 'cloudflare' in server:
                        print("✓ CloudFlare in server header")
                    if 'cloudfront' in server or 'amazons3' in server:
                        print("✓ AWS in server header")
                        
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_fingerprint())
