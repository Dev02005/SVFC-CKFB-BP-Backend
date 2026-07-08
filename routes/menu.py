from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from bson.objectid import ObjectId
import logging
from datetime import datetime
import re
from utils.db import custom_items_col, custom_categories_col, users_col

logger = logging.getLogger(__name__)
menu_bp = Blueprint('menu', __name__)

@menu_bp.route("/api/custom-items", methods=["GET"])
@jwt_required()
def get_custom_items():
    try:
        items = list(custom_items_col.find({}, {"_id": 0}))
        return jsonify({"success": True, "items": items}), 200
    except Exception as e:
        logger.error(f"Error fetching custom items: {str(e)}")
        return jsonify({"success": False, "error": "Failed to fetch custom items"}), 500

@menu_bp.route("/api/custom-items", methods=["POST"])
@jwt_required()
def add_custom_item():
    try:
        data = request.get_json()
        if not data or not data.get("name") or not data.get("price"):
            return jsonify({"success": False, "error": "Name and price are required"}), 400

        item = {
            "name": data["name"].strip(),
            "price": float(data["price"]),
            "category": data.get("category", "Custom").strip(),
            "imageUrl": (data.get("imageUrl") or "").strip(),
            "createdAt": datetime.now(),
            "createdBy": get_jwt_identity()
        }

        existing = custom_items_col.find_one({"name": item["name"]})
        if existing:
            return jsonify({"success": False, "error": "Item with this name already exists"}), 400

        custom_items_col.insert_one(item)
        logger.info(f"✅ Custom item added: {item['name']} - ₹{item['price']}")
        return jsonify({
            "success": True,
            "message": "Custom item added successfully",
            "item": {
                "name": item["name"],
                "price": item["price"],
                "category": item["category"],
                "imageUrl": item["imageUrl"]
            }
        }), 201
    except Exception as e:
        logger.error(f"Error adding custom item: {str(e)}")
        return jsonify({"success": False, "error": "Failed to add custom item"}), 500

@menu_bp.route("/api/custom-items/<name>", methods=["DELETE"])
@jwt_required()
def delete_custom_item(name):
    try:
        current_user_id = get_jwt_identity()
        user = users_col.find_one({"_id": ObjectId(current_user_id)})
        if not user or user.get('role') != 'admin':
            return jsonify({"success": False, "error": "Admin access required"}), 403

        result = custom_items_col.delete_one({"name": name})
        if result.deleted_count == 0:
            return jsonify({"success": False, "error": "Item not found"}), 404

        logger.info(f"✅ Custom item deleted: {name}")
        return jsonify({"success": True, "message": "Custom item deleted successfully"}), 200
    except Exception as e:
        logger.error(f"Error deleting custom item: {str(e)}")
        return jsonify({"success": False, "error": "Failed to delete custom item"}), 500

@menu_bp.route("/api/custom-items/<name>", methods=["PUT"])
@jwt_required()
def update_custom_item(name):
    try:
        current_user_id = get_jwt_identity()
        user = users_col.find_one({"_id": ObjectId(current_user_id)})
        if not user or user.get('role') != 'admin':
            return jsonify({"success": False, "error": "Admin access required"}), 403

        payload = request.get_json() or {}
        old_name = (name or "").strip()
        new_name = (payload.get("name") or "").strip()
        category = (payload.get("category") or "Custom").strip()
        image_url = (payload.get("imageUrl") or "").strip()

        if not old_name or not new_name:
            return jsonify({"success": False, "error": "Item name is required"}), 400
        if payload.get("price") is None:
            return jsonify({"success": False, "error": "Price is required"}), 400

        try:
            price = float(payload.get("price"))
            if price <= 0:
                raise ValueError()
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "Price must be a positive number"}), 400

        existing_item = custom_items_col.find_one({"name": {"$regex": f"^{re.escape(old_name)}$", "$options": "i"}})
        if not existing_item:
            return jsonify({"success": False, "error": "Item not found"}), 404

        if existing_item.get("name", "").lower() != new_name.lower():
            duplicate = custom_items_col.find_one({"name": {"$regex": f"^{re.escape(new_name)}$", "$options": "i"}})
            if duplicate:
                return jsonify({"success": False, "error": "Another item with this name already exists"}), 400

        custom_items_col.update_one(
            {"_id": existing_item["_id"]},
            {"$set": {
                "name": new_name, "price": price, "category": category,
                "imageUrl": image_url, "updatedAt": datetime.now(),
                "updatedBy": str(user.get("email", current_user_id))
            }}
        )
        logger.info(f"✅ Custom item updated: {existing_item.get('name')} -> {new_name}")
        return jsonify({
            "success": True,
            "message": "Custom item updated successfully",
            "item": {"name": new_name, "price": price, "category": category, "imageUrl": image_url}
        }), 200
    except Exception as e:
        logger.error(f"Error updating custom item: {str(e)}")
        return jsonify({"success": False, "error": "Failed to update custom item"}), 500

@menu_bp.route("/api/custom-categories", methods=["GET"])
@jwt_required()
def get_custom_categories():
    try:
        categories = list(custom_categories_col.find({}, {"_id": 0, "name": 1}).sort("name", 1))
        return jsonify({"success": True, "categories": [c["name"] for c in categories if c.get("name")]}), 200
    except Exception as e:
        logger.error(f"Error fetching custom categories: {str(e)}")
        return jsonify({"success": False, "error": "Failed to fetch custom categories"}), 500

@menu_bp.route("/api/custom-categories", methods=["POST"])
@jwt_required()
def add_custom_category():
    try:
        user_id = get_jwt_identity()
        user = users_col.find_one({"_id": ObjectId(user_id)})
        if not user or user.get("role") != "admin":
            return jsonify({"success": False, "error": "Admin access required"}), 403

        data = request.get_json() or {}
        category_name = (data.get("name") or "").strip()
        if not category_name:
            return jsonify({"success": False, "error": "Category name is required"}), 400

        existing = custom_categories_col.find_one({"name": {"$regex": f"^{re.escape(category_name)}$", "$options": "i"}})
        if existing:
            return jsonify({"success": False, "error": "Category already exists"}), 400

        custom_categories_col.insert_one({
            "name": category_name, "createdAt": datetime.now(),
            "createdBy": str(user.get("email", user_id))
        })
        logger.info(f"✅ Custom category added: {category_name}")
        return jsonify({"success": True, "message": "Category added successfully", "category": category_name}), 201
    except Exception as e:
        logger.error(f"Error adding custom category: {str(e)}")
        return jsonify({"success": False, "error": "Failed to add custom category"}), 500

@menu_bp.route("/api/custom-categories/<name>", methods=["DELETE"])
@jwt_required()
def delete_custom_category(name):
    try:
        user_id = get_jwt_identity()
        user = users_col.find_one({"_id": ObjectId(user_id)})
        if not user or user.get("role") != "admin":
            return jsonify({"success": False, "error": "Admin access required"}), 403

        category_name = (name or "").strip()
        existing = custom_categories_col.find_one({"name": {"$regex": f"^{re.escape(category_name)}$", "$options": "i"}})
        if not existing:
            return jsonify({"success": False, "error": "Category not found"}), 404

        custom_categories_col.delete_one({"_id": existing["_id"]})
        removed_items = custom_items_col.delete_many({"category": existing.get("name", category_name)}).deleted_count
        logger.info(f"✅ Custom category deleted: {existing.get('name', category_name)} (removed {removed_items} items)")
        return jsonify({
            "success": True, "message": "Category deleted successfully",
            "deletedCategory": existing.get("name", category_name), "removedItems": removed_items
        }), 200
    except Exception as e:
        logger.error(f"Error deleting custom category: {str(e)}")
        return jsonify({"success": False, "error": "Failed to delete custom category"}), 500
