from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from bson.objectid import ObjectId
from pymongo import ReturnDocument
import logging
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from utils.db import (
    bills_col, counter_col, users_col, business_now, 
    BUSINESS_TZ, setup_database_indexes
)

logger = logging.getLogger(__name__)
billing_bp = Blueprint('billing', __name__)

def build_bill_identifier_query(token_value, created_at_iso=None):
    token_str = str(token_value).strip()
    token_int = int(token_str)
    query = {
        "$or": [
            {"token": token_int}, {"token": token_str},
            {"billNo": token_int}, {"billNo": token_str},
        ]
    }
    if created_at_iso:
        query["$and"] = [{"createdAtISO": created_at_iso}]
    return query

def generate_unique_bill_no(now_utc):
    return f"UBN-{now_utc.strftime('%Y%m%d%H%M%S%f')}-{uuid4().hex[:8].upper()}"

def sanitize_bill_for_client(bill):
    if not isinstance(bill, dict): return bill
    sanitized = dict(bill)
    sanitized.pop("uniqueBillNo", None)
    return sanitized

def cleanup_old_bills():
    try:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=180)
        cutoff_iso = cutoff_date.isoformat()
        query = {"$or": [{"createdAt": {"$lt": cutoff_date}}, {"createdAtISO": {"$lt": cutoff_iso}}]}
        result = bills_col.delete_many(query)
        if result.deleted_count > 0:
            logger.info(f"🗑️ Cleanup: Deleted {result.deleted_count} bills older than 6 months")
        return result.deleted_count
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")
        return 0

def check_and_reset_daily_counter():
    try:
        now_local = business_now()
        counter = counter_col.find_one({"_id": "token"})
        if not counter:
            counter_col.insert_one({"_id": "token", "value": 1, "lastReset": now_local})
            return 1, False

        last_reset = counter.get("lastReset", now_local)
        if isinstance(last_reset, datetime):
            if last_reset.tzinfo is None:
                last_reset = last_reset.replace(tzinfo=timezone.utc)
            last_reset_local = last_reset.astimezone(BUSINESS_TZ)
        else:
            last_reset_local = now_local

        if last_reset_local.date() < now_local.date():
            counter_col.update_one({"_id": "token"}, {"$set": {"value": 1, "lastReset": now_local}})
            logger.info("♻️ Midnight Bill Counter Reset - Next Bill #1")
            return 1, True
        return counter.get("value", 1), False
    except Exception as e:
        logger.error(f"Error in counter reset check: {str(e)}")
        return 0, False

def validate_bill_data(data):
    if not isinstance(data, dict): return False, "Invalid request format"
    if not isinstance(data.get("items"), list): return False, "Items must be an array"
    total = data.get("total", 0)
    if not isinstance(total, (int, float)) or total < 0: return False, "Invalid total amount"
    
    payment = data.get("payment", "").strip()
    valid_payments = ["Cash", "Card", "UPI", "Cash / UPI", "Cash/UPI"]
    if payment and payment not in valid_payments: return False, f"Invalid payment method: {payment}"
    
    order_type = data.get("orderType", "").strip()
    valid_order_types = ["Dine-in", "Take Out", "Dine-in / Take Out", "Zomato", "Swiggy", "Swiggy / Zomato"]
    if order_type and order_type not in valid_order_types: return False, f"Invalid order type: {order_type}"
    
    return True, ""

@billing_bp.route("/api/token", methods=["GET"])
def get_token():
    try:
        _, was_reset = check_and_reset_daily_counter()
        if was_reset:
            return jsonify({"success": True, "token": 1}), 200

        token_doc = counter_col.find_one_and_update(
            {"_id": "token"}, {"$inc": {"value": 1}},
            return_document=ReturnDocument.BEFORE, upsert=True
        )
        if not token_doc or "value" not in token_doc:
            raise ValueError("Failed to fetch token from database")
        return jsonify({"success": True, "token": token_doc["value"]}), 200
    except Exception as e:
        logger.error(f"Error generating token: {str(e)}")
        return jsonify({"success": False, "error": "Failed to generate token"}), 500

@billing_bp.route("/api/token/current", methods=["GET"])
def get_current_token():
    try:
        _, was_reset = check_and_reset_daily_counter()
        if was_reset:
            return jsonify({"success": True, "token": 1}), 200
        token_doc = counter_col.find_one({"_id": "token"}) or {"value": 1}
        return jsonify({"success": True, "token": token_doc.get("value", 1)}), 200
    except Exception as e:
        logger.error(f"Error fetching current token: {str(e)}")
        return jsonify({"success": False, "error": "Failed to fetch current token"}), 500

@billing_bp.route("/api/cron/cleanup", methods=["GET", "POST"])
def api_cron_cleanup():
    try:
        deleted_count = cleanup_old_bills()
        setup_database_indexes()
        return jsonify({"success": True, "message": "Cleanup and indexing completed successfully", "deleted_count": deleted_count}), 200
    except Exception as e:
        logger.error(f"Error in cron cleanup: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@billing_bp.route("/api/bill", methods=["POST"])
def save_bill():
    try:
        data = request.get_json()
        if not data: return jsonify({"success": False, "error": "No data provided"}), 400
        is_valid, error_msg = validate_bill_data(data)
        if not is_valid: return jsonify({"success": False, "error": error_msg}), 400

        now_utc = datetime.now(timezone.utc)
        try:
            check_and_reset_daily_counter()
            token_doc = counter_col.find_one({"_id": "token"}) or {"value": 1}
            bill_number = int(token_doc.get("value", 1))
            counter_col.update_one({"_id": "token"}, {"$set": {"value": bill_number + 1, "lastReset": business_now()}}, upsert=True)
        except Exception:
            bill_number = int(data.get("token", 0)) or 0

        bill = {
            "items": data.get("items", []), "total": float(data.get("total", 0)),
            "payment": data.get("payment", "Unknown").strip(),
            "orderType": data.get("orderType", "Unknown").strip(),
            "token": int(bill_number), "uniqueBillNo": generate_unique_bill_no(now_utc),
            "createdAt": now_utc, "createdAtISO": now_utc.isoformat()
        }
        result = bills_col.insert_one(bill)
        logger.info(f"✅ Bill saved - Token: {bill['token']}, Total: ₹{bill['total']}, Items: {len(bill['items'])}")
        return jsonify({"success": True, "message": "Bill saved successfully", "billId": str(result.inserted_id), "token": bill["token"]}), 201
    except Exception as e:
        logger.error(f"Error saving bill: {str(e)}")
        return jsonify({"success": False, "error": "Failed to save bill"}), 500

@billing_bp.route("/api/bills", methods=["GET"])
def get_bills():
    try:
        days = request.args.get("days", type=int, default=None)
        payment = request.args.get("payment", default=None)
        order_type = request.args.get("orderType", default=None)
        limit = request.args.get("limit", type=int, default=1000)
        include_deleted = request.args.get("includeDeleted", default="false").lower() == "true"

        filter_query = {}
        if days: filter_query["createdAt"] = {"$gte": datetime.now() - timedelta(days=days)}
        if payment: filter_query["payment"] = payment
        if order_type: filter_query["orderType"] = order_type
        if not include_deleted: filter_query["deleted"] = {"$ne": True}

        bills = list(bills_col.find(filter_query, {"_id": 0}).sort([("createdAt", -1), ("token", -1)]).limit(limit))
        for bill in bills:
            if isinstance(bill.get('createdAt'), datetime):
                bill['createdAt'] = bill['createdAt'].isoformat()

        bills = [sanitize_bill_for_client(bill) for bill in bills]
        return jsonify(bills), 200
    except Exception as e:
        logger.error(f"Error fetching bills: {str(e)}")
        return jsonify([]), 200

@billing_bp.route("/api/bill/<token>", methods=["GET"])
def get_bill(token):
    try:
        bill = bills_col.find_one({"token": int(token)}, {"_id": 0})
        if bill:
            bill = next(bills_col.find({"token": int(token)}, {"_id": 0}).sort("createdAt", -1).limit(1), None)
        if not bill:
            return jsonify({"success": False, "error": "Bill not found"}), 404
        return jsonify({"success": True, "bill": sanitize_bill_for_client(bill)}), 200
    except ValueError:
        return jsonify({"success": False, "error": "Invalid token"}), 400
    except Exception as e:
        logger.error(f"Error fetching bill: {str(e)}")
        return jsonify({"success": False, "error": "Failed to fetch bill"}), 500

@billing_bp.route("/api/bill/<token>/delete", methods=["PUT"])
@jwt_required()
def delete_bill(token):
    try:
        user = users_col.find_one({"_id": ObjectId(get_jwt_identity())})
        if not user or user.get('role') != 'admin':
            return jsonify({"success": False, "error": "Admin access required"}), 403
        
        body = request.get_json(silent=True) or {}
        created_at_iso = (body.get("createdAtISO") or request.args.get("createdAtISO") or request.args.get("createdAt") or "").strip()
        bill_query = build_bill_identifier_query(token, created_at_iso or None)
        result = bills_col.update_one(bill_query, {"$set": {"deleted": True}})
        
        if result.matched_count == 0: return jsonify({"success": False, "error": "Bill not found"}), 404
        logger.info(f"✅ Bill marked as deleted - Token: {int(token)}")
        return jsonify({"success": True, "message": "Bill marked as deleted"}), 200
    except ValueError:
        return jsonify({"success": False, "error": "Invalid token"}), 400
    except Exception:
        return jsonify({"success": False, "error": "Failed to delete bill"}), 500

@billing_bp.route("/api/bill/<token>/restore", methods=["PUT"])
@jwt_required()
def restore_bill(token):
    try:
        user = users_col.find_one({"_id": ObjectId(get_jwt_identity())})
        if not user or user.get('role') != 'admin':
            return jsonify({"success": False, "error": "Admin access required"}), 403

        body = request.get_json(silent=True) or {}
        created_at_iso = (body.get("createdAtISO") or request.args.get("createdAtISO") or request.args.get("createdAt") or "").strip()
        bill_query = build_bill_identifier_query(token, created_at_iso or None)
        result = bills_col.update_one(bill_query, {"$set": {"deleted": False}})
        
        if result.matched_count == 0: return jsonify({"success": False, "error": "Bill not found"}), 404
        logger.info(f"✅ Bill restored - Token: {int(token)}")
        return jsonify({"success": True, "message": "Bill restored successfully"}), 200
    except ValueError:
        return jsonify({"success": False, "error": "Invalid token"}), 400
    except Exception:
        return jsonify({"success": False, "error": "Failed to restore bill"}), 500

@billing_bp.route("/api/bill/<token>/permanent-delete", methods=["DELETE"])
@jwt_required()
def permanent_delete_bill(token):
    try:
        user = users_col.find_one({"_id": ObjectId(get_jwt_identity())})
        if not user or user.get('role') != 'admin':
            return jsonify({"success": False, "error": "Admin access required"}), 403

        body = request.get_json(silent=True) or {}
        created_at_iso = str(body.get("createdAtISO") or request.args.get("createdAtISO") or request.args.get("createdAt") or "").strip()
        bill_query = build_bill_identifier_query(token, created_at_iso or None)
        result = bills_col.delete_one(bill_query)
        
        if result.deleted_count == 0: return jsonify({"success": False, "error": "Bill not found"}), 404
        logger.warning(f"⚠️ Bill permanently deleted - Token: {int(token)}")
        return jsonify({"success": True, "message": "Bill permanently deleted"}), 200
    except ValueError:
        return jsonify({"success": False, "error": "Invalid token"}), 400
    except Exception:
        return jsonify({"success": False, "error": "Failed to permanently delete bill"}), 500
