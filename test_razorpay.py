# test_razorpay.py
import os
import razorpay

key_id = os.getenv("RAZORPAY_KEY_ID")
key_secret = os.getenv("RAZORPAY_KEY_SECRET")

print("Key id:", key_id)
print("Secret present:", bool(key_secret))

if not key_id or not key_secret:
    print("RAZORPAY keys missing in env. set them and re-run.")
    raise SystemExit(1)

client = razorpay.Client(auth=(key_id, key_secret))

try:
    # create a tiny test order
    order = client.order.create({"amount": 10, "currency": "INR", "receipt": "test_receipt", "payment_capture": 1})
    print("Order created:", order)
except Exception as e:
    print("Order create failed:", type(e), e)
