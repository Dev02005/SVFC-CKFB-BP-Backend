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
- **Core:** Python 3 (Flask web framework using Blueprint Architecture)
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

## Project Structure

The codebase is organized into a modular structure for easy maintenance:

```text
/
├── routes/                  # API endpoint grouped by feature (Flask Blueprints)
│   ├── auth.py              # Login and token verification routes
│   ├── billing.py           # Bill creation, fetching, deletion, and cron cleanup
│   └── menu.py              # Custom menu items and categories management
├── utils/                   # Shared helper functions
│   └── db.py                # MongoDB connection, password hashing, and indexing
├── static/                  # Frontend assets
│   ├── app.jsx              # Readable React Source Code
│   ├── app.js               # Compiled JavaScript (Loaded by browser)
│   ├── style.css            # Stylesheets and mobile responsive queries
│   └── manifest.json        # PWA Configuration
├── app.py                   # Main backend entry point (registers routes & boots server)
├── index.html               # Main frontend entry point
└── requirements.txt         # Python dependencies
```



## Deployment

The application includes a `vercel.json` configuration and is ready for Vercel deployment as a serverless Python Flask application.

---

## License

This software and its associated documentation are the exclusive proprietary property of dev. All rights reserved. Use, reproduction, or distribution without explicit permission is strictly prohibited. For details, see the [LICENSE](LICENSE) file.
