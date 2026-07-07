# Sri Vengamamba Food Court (SVFC) - Chinese Kitchen Billing Portal

A Point of Sale (POS) and Analytics system designed for Sri Vengamamba Food Court - Chinese Kitchen / Juice Bar. The application features an interactive billing panel, printing support (optimized for thermal slips), analytics charts, PWA (offline capability via Service Worker), and secure cashier/admin role authentication.

---

## Features

- **Billing & POS Terminal:** Add, edit, and delete items in real-time, compute totals, customize order types (Dine-in, Take Out, Swiggy, Zomato) and payment methods (Cash, Card, UPI).
- **12-Hour Clock:** Displays the current date and time on screen and prints in standard 12-hour AM/PM format.
- **Thermal Print Layout:** Automatic page formatting configured for 56mm wide thermal printers with zero-margin stacking to avoid spacing gaps in physical receipts.
- **Analytics Dashboard:** Visualizes weekly and monthly sales distribution, payment breakdowns, hourly sales frequencies, and peak billing times.
- **Excel & PDF Exports:** Download standard CSV or Excel-compatible billing records.
- **Cashier & Admin Authorization:** Separates admin actions (e.g., managing menu items and categories) from cashier billing workflows.
- **PWA Capabilities:** Service Worker registration and caching allow offline loading and native-like installation.

---

## Technology Stack

### Backend
- **Core:** Python 3 (Flask web framework)
- **Database:** MongoDB Atlas (via PyMongo client)
- **Security:** Flask-JWT-Extended (JSON Web Tokens), bcrypt (password hashing)
- **Optimization:** Flask-Compress (gzip compression)
- **Configuration:** Python-dotenv

### Frontend
- **Framework:** React 18 & ReactDOM 18 (loaded via unpkg CDN)
- **Styling:** Vanilla CSS (responsive grid layout, print stylesheets)
- **Visualization:** Chart.js
- **Exports:** SheetJS (xlsx)

---

## Setup & Installation

### Prerequisite
Make sure you have Python 3.8+ and Node.js (optional, for asset changes) installed on your system.

### 1. Install Dependencies
Install the required python packages:
```bash
pip install -r requirements.txt
```

### 2. Configure .env File
Create a .env file in the root folder with the following variables:
```env
MONGO_URI=mongodb+srv://<username>:<password>@cluster.mongodb.net/svfc_pos?retryWrites=true&w=majority
JWT_SECRET_KEY=your-secure-jwt-key
PORT=5000
DEBUG=True
```

---


## Deployment

The application includes a vercel.json configuration and is ready for Vercel deployment as a serverless Python Flask application.

---

## License

This software and its associated documentation are the exclusive proprietary property of dev aka Praneeth Karri. All rights reserved. Use, reproduction, or distribution without explicit permission is strictly prohibited. For details, see the [LICENSE](LICENSE) file.
