# test_ors_matrix.py
import os, json, requests
from dotenv import load_dotenv

load_dotenv()
KEY = os.getenv("ORS_API_KEY")
if not KEY:
    raise SystemExit("ORS_API_KEY not found in .env")

# pick two hubs from your hub_coords.json
# make sure hub_coords.json is in same folder or adjust path
with open("data/hub_coords.json", "r", encoding="utf-8") as f:
    hubs = json.load(f)

# Example: choose Ludhiana City Centre and Jalandhar City Centre
o_name = "Ludhiana - City Centre (Railway Station / Bus Stand)"
d_name = "Jalandhar - City Centre (Bus Stand / Railway Station)"

if o_name not in hubs or d_name not in hubs:
    print("Hub names not found in hub_coords.json. Available keys:")
    print(list(hubs.keys())[:10])
    raise SystemExit(1)

o = hubs[o_name]
d = hubs[d_name]

# ORS expects [lng, lat]
body = {
    "locations": [[o["lng"], o["lat"]], [d["lng"], d["lat"]]],
    "metrics": ["distance"],
    "units": "m"
}

resp = requests.post(
    "https://api.openrouteservice.org/v2/matrix/driving-car",
    headers={"Authorization": KEY, "Content-Type": "application/json"},
    json=body,
    timeout=30
)

print("HTTP", resp.status_code)
try:
    j = resp.json()
except Exception:
    print("Response text:", resp.text)
    raise

if resp.status_code != 200:
    print("Error from ORS:", j)
else:
    # distances is a 2x2 matrix for this request
    distances = j.get("distances")
    if distances:
        meters = distances[0][1]  # origin row 0 -> destination col 1
        km = meters / 1000.0
        print(f"Driving distance {o_name} → {d_name} = {meters:.1f} m = {km:.2f} km")
    else:
        print("No distances returned:", j)
