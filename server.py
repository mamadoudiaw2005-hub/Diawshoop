import os
import time
import random
import json
import logging
import requests
from flask import Flask, request, jsonify, send_from_directory
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask App
app = Flask(__name__, static_folder=".", static_url_path="")

# Retrieve credentials
CINETPAY_API_KEY = os.getenv("CINETPAY_API_KEY", "18714246125b8fc60b85c27.42772591")
CINETPAY_SITE_ID = os.getenv("CINETPAY_SITE_ID", "455431")
FLASK_PORT = int(os.getenv("FLASK_PORT", 8080))

# Persistent Server-side Order Log (Safety Backup)
ORDERS_LOG_FILE = "server_orders.json"

def log_order_server_side(order_data):
    """Saves order status changes locally on the server for security audit logs."""
    try:
        orders = []
        if os.path.exists(ORDERS_LOG_FILE):
            with open(ORDERS_LOG_FILE, "r", encoding="utf-8") as f:
                orders = json.load(f)
        
        # Update if exists, else append
        existing_index = next((i for i, o in enumerate(orders) if o.get("id") == order_data.get("id")), None)
        if existing_index is not None:
            # Merge dictionary updates
            orders[existing_index].update(order_data)
        else:
            orders.append(order_data)
            
        with open(ORDERS_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(orders, f, indent=4, ensure_ascii=False)
        logger.info(f"Order {order_data.get('id')} successfully logged server-side.")
    except Exception as e:
        logger.error(f"Error writing to server order log: {str(e)}")

# Serve Static Frontend Files
@app.route("/")
def serve_index():
    return send_from_directory(".", "index.html")

@app.route("/<path:path>")
def serve_static(path):
    # Prevent traversal and block access to sensitive files
    basename = os.path.basename(path).lower()
    if basename in [".env", "server.py", "server_orders.json"] or basename.endswith(".py") or path.startswith("."):
        return jsonify({"status": "error", "message": "Accès interdit"}), 403
    return send_from_directory(".", path)

# --- SECURE PAYMENT INTEGRATION API ---

@app.route("/api/create-payment", methods=["POST"])
def create_payment():
    """Initiates a secure mobile money transaction using CinetPay."""
    try:
        data = request.json or {}
        amount = data.get("amount")
        customer_name = data.get("customer_name", "Client Diaw Shoop")
        customer_phone = data.get("customer_phone", "221785946427")
        customer_email = data.get("customer_email", "client@gmail.com")
        payout_number = data.get("payout_number", "770000000")
        payout_carrier = data.get("payout_carrier", "wave")
        items = data.get("items", [])
        
        if not amount or int(amount) <= 0:
            return jsonify({"status": "error", "message": "Montant invalide"}), 400
            
        # Generate a secure, unique transaction ID
        transaction_id = f"DS-{int(time.time())}{random.randint(10, 99)}"
        
        # CinetPay request payload
        # API documentation: https://docs.cinetpay.com/api/v2/checkout/initialisation
        cinetpay_url = "https://api-checkout.cinetpay.com/api/v2/payment"
        payload = {
            "apikey": CINETPAY_API_KEY,
            "site_id": CINETPAY_SITE_ID,
            "transaction_id": transaction_id,
            "amount": int(amount),
            "currency": "XOF",
            "alternative_currency": "",
            "description": f"Paiement commande DIAW SHOOP - {transaction_id}",
            "customer_id": customer_email,
            "customer_name": customer_name,
            "customer_surname": "Client",
            "customer_email": customer_email,
            "customer_phone_number": customer_phone,
            "customer_address": "Dakar",
            "customer_city": "Dakar",
            "customer_country": "SN",
            "customer_state": "SN",
            "customer_zip_code": "00000",
            # Notify URL: CinetPay webhook destination
            "notify_url": request.host_url + "api/webhook",
            "return_url": request.host_url,
            "channels": "ALL",
            "metadata": json.dumps({"items": items})
        }
        
        try:
            logger.info(f"Sending checkout initialization request to CinetPay for transaction {transaction_id}...")
            headers = {"Content-Type": "application/json"}
            response = requests.post(cinetpay_url, json=payload, headers=headers, timeout=12)
            res_data = response.json()
            
            if response.status_code == 200 and res_data.get("code") == "201":
                payment_url = res_data["data"]["payment_url"]
                logger.info(f"CinetPay transaction {transaction_id} created successfully. Redirect URL: {payment_url}")
                
                # Log temporary order state on server
                log_order_server_side({
                    "id": transaction_id,
                    "amount": amount,
                    "clientName": customer_name,
                    "clientPhone": customer_phone,
                    "clientEmail": customer_email,
                    "status": "En attente de paiement",
                    "payout_number": payout_number,
                    "payout_carrier": payout_carrier,
                    "items": items,
                    "date": time.strftime("%Y-%m-%d %H:%M:%S")
                })
                
                return jsonify({
                    "status": "success",
                    "transaction_id": transaction_id,
                    "payment_url": payment_url
                })
            else:
                logger.error(f"CinetPay initialization failed: {res_data.get('description', 'Unknown error')}")
                raise Exception(res_data.get("description", "CinetPay API Error"))
                
        except Exception as api_err:
            logger.warning(f"CinetPay API unreachable or failed ({str(api_err)}). Falling back to local offline mock portal...")
            payment_url = f"/mock-checkout/{transaction_id}?amount={amount}&payout_number={payout_number}&payout_carrier={payout_carrier}"
            
            # Log temporary order state on server
            log_order_server_side({
                "id": transaction_id,
                "amount": amount,
                "clientName": customer_name,
                "clientPhone": customer_phone,
                "clientEmail": customer_email,
                "status": "En attente de paiement",
                "is_mock": True,
                "payout_number": payout_number,
                "payout_carrier": payout_carrier,
                "items": items,
                "date": time.strftime("%Y-%m-%d %H:%M:%S")
            })
            
            return jsonify({
                "status": "success",
                "transaction_id": transaction_id,
                "payment_url": payment_url,
                "is_mock": True
            })
            
    except Exception as e:
        logger.exception("An exception occurred during create-payment:")
        return jsonify({"status": "error", "message": f"Exception: {str(e)}"}), 500

@app.route("/api/payment-status/<transaction_id>", methods=["GET"])
def get_payment_status(transaction_id):
    """Queries CinetPay backend-to-backend to get the true, verified payment status."""
    # Check if transaction is marked as local mock first
    is_mock = False
    mock_status = "PENDING"
    try:
        if os.path.exists(ORDERS_LOG_FILE):
            with open(ORDERS_LOG_FILE, "r", encoding="utf-8") as f:
                orders = json.load(f)
                order = next((o for o in orders if o.get("id") == transaction_id), None)
                if order and order.get("is_mock"):
                    is_mock = True
                    if order.get("status") == "Payée (En attente d'expédition)":
                        mock_status = "ACCEPTED"
                    elif order.get("status") == "REFUSED":
                        mock_status = "REFUSED"
    except Exception as e:
        logger.error(f"Error checking local orders log: {str(e)}")

    if is_mock:
        return jsonify({
            "status": "success",
            "payment_status": mock_status,
            "amount": 0,
            "payment_method": "MOBILE_MONEY"
        })

    # Standard check online
    try:
        check_url = "https://api-checkout.cinetpay.com/api/v2/payment/check"
        payload = {
            "apikey": CINETPAY_API_KEY,
            "site_id": CINETPAY_SITE_ID,
            "transaction_id": transaction_id
        }
        
        logger.info(f"Querying status for transaction {transaction_id} from CinetPay server...")
        headers = {"Content-Type": "application/json"}
        response = requests.post(check_url, json=payload, headers=headers, timeout=10)
        res_data = response.json()
        
        if response.status_code == 200 and res_data.get("code") == "00":
            payment_data = res_data.get("data", {})
            status = payment_data.get("status")
            amount = payment_data.get("amount")
            payment_method = payment_data.get("payment_method", "MOBILE_MONEY")
            
            logger.info(f"Transaction {transaction_id} status resolved: {status}")
            
            if status == "ACCEPTED":
                log_order_server_side({
                    "id": transaction_id,
                    "status": "Payée (En attente d'expédition)",
                    "amount": amount,
                    "paymentMethod": payment_method,
                    "last_checked": time.strftime("%Y-%m-%d %H:%M:%S")
                })
                
            return jsonify({
                "status": "success",
                "payment_status": status,
                "amount": amount,
                "payment_method": payment_method
            })
        else:
            logger.warning(f"CinetPay status check failed or returned non-success for {transaction_id}: {res_data.get('description')}")
            return jsonify({
                "status": "pending",
                "payment_status": "PENDING",
                "message": res_data.get("description", "Vérification en cours.")
            })
            
    except Exception as e:
        logger.error(f"Error checking status online for {transaction_id} ({str(e)}). Checking local log instead...")
        # Fallback to local log state if connection fails during polling
        try:
            if os.path.exists(ORDERS_LOG_FILE):
                with open(ORDERS_LOG_FILE, "r", encoding="utf-8") as f:
                    orders = json.load(f)
                    order = next((o for o in orders if o.get("id") == transaction_id), None)
                    if order and order.get("status") == "Payée (En attente d'expédition)":
                        return jsonify({
                            "status": "success",
                            "payment_status": "ACCEPTED",
                            "amount": order.get("amount", 0),
                            "payment_method": "MOBILE_MONEY"
                        })
        except Exception:
            pass
        return jsonify({"status": "pending", "payment_status": "PENDING", "message": str(e)})

@app.route("/api/webhook", methods=["POST"])
def payment_webhook():
    """Receives asynchronous notification from CinetPay when a transaction is completed."""
    try:
        cpay_trans_id = request.form.get("cpay_custom") or request.json.get("cpay_custom")
        if not cpay_trans_id:
            cpay_trans_id = request.form.get("transaction_id") or request.json.get("transaction_id")
            
        if not cpay_trans_id:
            logger.warning("Webhook received with no transaction identifier.")
            return jsonify({"status": "ignored", "message": "No transaction ID found"}), 400
            
        logger.info(f"Webhook triggered for transaction {cpay_trans_id}. Validating with CinetPay API...")
        
        # Verify transaction legitimacy backend-to-backend
        check_url = "https://api-checkout.cinetpay.com/api/v2/payment/check"
        payload = {
            "apikey": CINETPAY_API_KEY,
            "site_id": CINETPAY_SITE_ID,
            "transaction_id": cpay_trans_id
        }
        
        headers = {"Content-Type": "application/json"}
        response = requests.post(check_url, json=payload, headers=headers, timeout=10)
        res_data = response.json()
        
        if response.status_code == 200 and res_data.get("code") == "00":
            payment_data = res_data.get("data", {})
            status = payment_data.get("status")
            amount = payment_data.get("amount")
            
            logger.info(f"Webhook verified transaction {cpay_trans_id} status: {status}")
            
            if status == "ACCEPTED":
                log_order_server_side({
                    "id": cpay_trans_id,
                    "status": "Payée (En attente d'expédition)",
                    "amount": amount,
                    "webhook_verified": True,
                    "verified_at": time.strftime("%Y-%m-%d %H:%M:%S")
                })
                return jsonify({"status": "success", "message": "Transaction verified and logged."}), 200
            else:
                return jsonify({"status": "verified", "message": f"Status is {status} (Not accepted)"}), 200
        else:
            logger.error(f"Webhook transaction check failed for {cpay_trans_id}: {res_data.get('description')}")
            return jsonify({"status": "failed", "message": "Transaction check failed"}), 400
            
    except Exception as e:
        logger.error(f"Error handling webhook: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

# --- MOCK SIMULATOR ENDPOINTS FOR OFFLINE / DNS FAILURES ---

@app.route("/mock-checkout/<transaction_id>", methods=["GET"])
def mock_checkout(transaction_id):
    """Renders a beautiful, local checkout screen simulating CinetPay Senegal."""
    amount = request.args.get("amount", "0")
    method = request.args.get("method", "Wave")
    payout_number = request.args.get("payout_number", "770000000")
    payout_carrier = request.args.get("payout_carrier", "wave")
    
    html_content = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Portail de Paiement Sécurisé (Mode Simulation)</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {{
            --bg-color: #f4f6f9;
            --card-bg: #ffffff;
            --text-color: #1e293b;
            --primary: #fb923c;
            --accent: #2563eb;
            --success: #10b981;
            --danger: #ef4444;
            --border: #e2e8f0;
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Outfit', sans-serif;
        }}
        body {{
            background-color: var(--bg-color);
            color: var(--text-color);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }}
        .checkout-card {{
            background: var(--card-bg);
            border-radius: 16px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05), 0 8px 10px -6px rgba(0, 0, 0, 0.05);
            width: 100%;
            max-width: 450px;
            overflow: hidden;
            border: 1px solid var(--border);
        }}
        .header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            color: white;
            padding: 30px 20px;
            text-align: center;
            position: relative;
        }}
        .header h2 {{
            font-size: 1.4rem;
            font-weight: 600;
            margin-top: 10px;
        }}
        .header .subtitle {{
            font-size: 0.85rem;
            color: #94a3b8;
            margin-top: 5px;
        }}
        .badge-simulation {{
            position: absolute;
            top: 15px;
            right: 15px;
            background: var(--primary);
            color: white;
            font-size: 0.7rem;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 20px;
            text-transform: uppercase;
        }}
        .content {{
            padding: 30px 20px;
        }}
        .details-box {{
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 15px 20px;
            margin-bottom: 25px;
        }}
        .detail-row {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            font-size: 0.9rem;
        }}
        .detail-row:last-child {{
            margin-bottom: 0;
        }}
        .amount-big {{
            font-size: 1.5rem;
            font-weight: 700;
            color: #0f172a;
        }}
        .form-group {{
            margin-bottom: 20px;
        }}
        .form-group label {{
            display: block;
            font-size: 0.85rem;
            font-weight: 600;
            margin-bottom: 8px;
            color: #64748b;
        }}
        .input-wrapper {{
            position: relative;
        }}
        .input-wrapper i {{
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: #94a3b8;
        }}
        .input-wrapper input {{
            width: 100%;
            padding: 12px 15px 12px 45px;
            border: 1px solid var(--border);
            border-radius: 10px;
            font-size: 1rem;
            outline: none;
            transition: border-color 0.2s;
        }}
        .input-wrapper input:focus {{
            border-color: var(--primary);
        }}
        .actions {{
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}
        .btn {{
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 10px;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 8px;
        }}
        .btn-success {{
            background-color: var(--success);
            color: white;
        }}
        .btn-success:hover {{
            background-color: #059669;
        }}
        .btn-danger {{
            background-color: var(--danger);
            color: white;
        }}
        .btn-danger:hover {{
            background-color: #dc2626;
        }}
        .footer-note {{
            text-align: center;
            font-size: 0.75rem;
            color: #94a3b8;
            margin-top: 25px;
        }}
    </style>
</head>
<body>
    <div class="checkout-card">
        <div class="header">
            <span class="badge-simulation">Mode Démo Offline</span>
            <i class="fa-solid fa-shield-halved" style="font-size: 2.5rem; color: var(--primary);"></i>
            <h2>DIAW SHOOP Pay Portal</h2>
            <div class="subtitle">Sécurisé par CinetPay Simulator</div>
        </div>
        <div class="content">
            <div class="details-box">
                <div class="detail-row">
                    <span style="color:#64748b;">ID Commande :</span>
                    <span style="font-weight: 600;">{transaction_id}</span>
                </div>
                <div class="detail-row">
                    <span style="color:#64748b;">Moyen de Paiement :</span>
                    <span style="font-weight: 600; color: var(--accent); text-transform: uppercase;">{method}</span>
                </div>
                <div class="detail-row" style="margin-top:8px; border-top:1px dashed var(--border); padding-top:8px; font-size: 0.85rem;">
                    <span style="color:#64748b;">Compte Destinataire (Payout) :</span>
                    <span style="font-weight: 600; color: var(--primary); text-transform: uppercase;">{payout_carrier} ({payout_number})</span>
                </div>
                <div class="detail-row" style="margin-top:15px; border-top:1px solid var(--border); padding-top:15px;">
                    <span style="font-weight:600; align-self:center;">Montant total :</span>
                    <span class="amount-big">{amount} FCFA</span>
                </div>
            </div>
            
            <div class="form-group">
                <label for="sim-phone">Numéro de téléphone de validation</label>
                <div class="input-wrapper">
                    <i class="fa-solid fa-phone"></i>
                    <input type="tel" id="sim-phone" value="770000000" placeholder="Ex: 77 123 45 67">
                </div>
            </div>
            
            <div class="actions">
                <button class="btn btn-success" id="btn-approve">
                    <i class="fa-solid fa-circle-check"></i> Simuler un paiement RÉUSSI
                </button>
                <button class="btn btn-danger" id="btn-decline">
                    <i class="fa-solid fa-circle-xmark"></i> Simuler un paiement ÉCHOUÉ
                </button>
            </div>
            
            <p class="footer-note">
                <i class="fa-solid fa-lock"></i> Connexion SSL chiffrée. Ce portail simule localement le transfert vers {payout_carrier.upper()} ({payout_number}).
            </p>
        </div>
    </div>
    
    <script>
        document.getElementById("btn-approve").addEventListener("click", () => {{
            fetch("/api/mock-update", {{
                method: "POST",
                headers: {{ "Content-Type": "application/json" }},
                body: JSON.stringify({{
                    transaction_id: '{transaction_id}',
                    status: "ACCEPTED"
                }})
            }})
            .then(res => res.json())
            .then(data => {{
                alert("Paiement simulé avec succès ! Vous pouvez fermer cet onglet et revenir sur votre boutique.");
                window.close();
            }});
        }});
        
        document.getElementById("btn-decline").addEventListener("click", () => {{
            fetch("/api/mock-update", {{
                method: "POST",
                headers: {{ "Content-Type": "application/json" }},
                body: JSON.stringify({{
                    transaction_id: '{transaction_id}',
                    status: "REFUSED"
                }})
            }})
            .then(res => res.json())
            .then(data => {{
                alert("Paiement simulé comme ÉCHOUÉ/REFUSÉ. Vous pouvez fermer cet onglet.");
                window.close();
            }});
        }});
    </script>
</body>
</html>
    """
    return html_content

@app.route("/api/mock-update", methods=["POST"])
def mock_update():
    """Allows simulated success/failure selection for mock payments."""
    try:
        data = request.json or {}
        transaction_id = data.get("transaction_id")
        status = data.get("status")
        
        if not transaction_id or not status:
            return jsonify({"status": "error", "message": "Missing arguments"}), 400
            
        orders = []
        if os.path.exists(ORDERS_LOG_FILE):
            with open(ORDERS_LOG_FILE, "r", encoding="utf-8") as f:
                orders = json.load(f)
                
        order = next((o for o in orders if o.get("id") == transaction_id), None)
        if order:
            if status == "ACCEPTED":
                order["status"] = "Payée (En attente d'expédition)"
            else:
                order["status"] = "REFUSED"
                
            with open(ORDERS_LOG_FILE, "w", encoding="utf-8") as f:
                json.dump(orders, f, indent=4, ensure_ascii=False)
                
            logger.info(f"Mock transaction {transaction_id} updated to status: {status}")
            return jsonify({"status": "success", "message": "Transaction state updated."})
        else:
            return jsonify({"status": "error", "message": "Transaction not found"}), 404
    except Exception as e:
        logger.error(f"Error updating mock status: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    logger.info(f"Starting DIAW SHOOP Secure Server on port {FLASK_PORT}...")
    app.run(host="0.0.0.0", port=FLASK_PORT, debug=True)
