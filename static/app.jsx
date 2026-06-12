const { useState, useEffect, useCallback, useMemo, useRef } = React;

// ==========================================
// API UTILS & HELPER FUNCTIONS
// ==========================================
const apiUrl = (path) => path;

const getAuthHeaders = () => {
  const token = localStorage.getItem('authToken') || localStorage.getItem('token');
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  };
};

const getAuthHeadersOnly = () => {
  const token = localStorage.getItem('authToken') || localStorage.getItem('token');
  return { 'Authorization': `Bearer ${token}` };
};

const getCurrentUser = () => {
  try {
    const raw = localStorage.getItem('user');
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
};

const isAdmin = () => {
  const user = getCurrentUser();
  return user && user.role === 'admin';
};

const logout = () => {
  localStorage.removeItem('authToken');
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  window.location.hash = '#/login';
};

// ==========================================
// TOAST POPUP COMPONENT
// ==========================================
function StatusPopup({ msg, type, visible }) {
  if (!visible || !msg) return null;

  let color = '#10b981'; // default success green
  if (type === 'gold') color = '#f59e0b';
  if (type === 'danger') color = '#ef4444';

  const toastStyle = {
    background: '#1a1e24',
    borderLeft: `4px solid ${color}`,
    color: '#f3f4f6',
    boxShadow: '0 4px 6px rgba(0,0,0,0.3)'
  };

  return (
    <div className={`status-popup status-popup--${type}`} role="alert" style={toastStyle}>
      {msg}
    </div>
  );
}

// ==========================================
// SETTINGS DROPDOWN COMPONENT
// ==========================================
function SettingsDropdown({ user, onAddCategory, onDeleteCategory, onAddMenu, onEditMenu, onDeleteMenu, onLogout }) {
  const [open, setOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [catOpen, setCatOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const ref = useRef(null);

  const role = user?.role || 'staff';
  let label = 'Staff';
  if (user?.username) {
    const m = user.username.match(/^casher\s*(\d+)$/i);
    if (m) label = `Cashier ${m[1]}`;
    else if (/^admin$/i.test(user.username)) label = 'Admin';
    else label = user.username.charAt(0).toUpperCase() + user.username.slice(1);
  } else {
    label = role.charAt(0).toUpperCase() + role.slice(1);
  }

  useEffect(() => {
    const handler = e => {
      if (ref.current && !ref.current.contains(e.target)) {
        setOpen(false);
        setEditOpen(false); setCatOpen(false); setMenuOpen(false);
      }
    };
    document.addEventListener('click', handler);
    return () => document.removeEventListener('click', handler);
  }, []);

  return (
    <div className="settings-container" ref={ref}>
      <button
        className="header-icon-btn settings-btn"
        onClick={e => { e.stopPropagation(); setOpen(v => !v); }}
        title="Settings"
      >
        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="btn-logo-svg">
          <circle cx="12" cy="12" r="3"></circle>
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
        </svg>
      </button>
      {open && (
        <div className="settings-dropdown">
          <div className="settings-header-label">{label}</div>
          {isAdmin() && (
            <>
              <button
                className={`dropdown-menu-btn edit-menu-toggle ${editOpen ? 'expanded' : ''}`}
                onClick={e => { e.stopPropagation(); setEditOpen(v => !v); if (editOpen) { setCatOpen(false); setMenuOpen(false); } }}
              >
                Edit Itenary <span className="chevron">▼</span>
              </button>
              {editOpen && (
                <div className="edit-menu-submenu active">
                  <hr className="settings-divider" />
                  <div className="settings-group">
                    <button
                      className={`settings-group-toggle ${catOpen ? 'expanded' : ''}`}
                      onClick={e => { e.stopPropagation(); setCatOpen(v => !v); setMenuOpen(false); }}
                    >
                      Category <span className="chevron">▼</span>
                    </button>
                    {catOpen && (
                      <div className="settings-submenu active">
                        <button className="dropdown-menu-btn" onClick={() => { setOpen(false); onAddCategory(); }}>Add Category</button>
                        <button className="dropdown-menu-btn" onClick={() => { setOpen(false); onDeleteCategory(); }}>Delete Category</button>
                      </div>
                    )}
                  </div>
                  <div className="settings-group">
                    <button
                      className={`settings-group-toggle ${menuOpen ? 'expanded' : ''}`}
                      onClick={e => { e.stopPropagation(); setMenuOpen(v => !v); setCatOpen(false); }}
                    >
                      Menu <span className="chevron">▼</span>
                    </button>
                    {menuOpen && (
                      <div className="settings-submenu active">
                        <button className="dropdown-menu-btn" onClick={() => { setOpen(false); onAddMenu(); }}>Add Menu</button>
                        <button className="dropdown-menu-btn" onClick={() => { setOpen(false); onEditMenu(); }}>Edit Menu</button>
                        <button className="dropdown-menu-btn" onClick={() => { setOpen(false); onDeleteMenu(); }}>Delete Menu</button>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </>
          )}
          <hr className="settings-divider" />
          <button className="dropdown-menu-btn logout-btn" onClick={onLogout}>Logout</button>
        </div>
      )}
    </div>
  );
}

// ==========================================
// MENU CATALOG PANEL COMPONENT
// ==========================================
const MenuPanel = React.memo(function MenuPanel({ menuData, activeCategory, setActiveCategory, onAddItem }) {
  const categories = Object.keys(menuData);
  const current = activeCategory && menuData[activeCategory] ? activeCategory : categories[0] || '';
  const items = menuData[current] || [];

  return (
    <>
      <div className="tabs">
        {categories.map(cat => (
          <button
            key={cat}
            className={cat === current ? 'active' : ''}
            onClick={() => setActiveCategory(cat)}
          >
            {cat}
          </button>
        ))}
      </div>
      <div className="menu">
        {items.map((item, idx) => {
          const name = Array.isArray(item) ? item[0] : item.name;
          const price = Array.isArray(item) ? item[1] : item.price;
          const image = Array.isArray(item) ? item[2] : item.imageUrl;
          return (
            <div
              key={`${name}-${idx}`}
              className="menu-item"
              style={image ? { backgroundImage: `url('${image}')`, backgroundSize: 'cover', backgroundPosition: 'center' } : {}}
              onClick={() => onAddItem(name, price)}
            >
              <div className="menu-item-info">
                <div className="item-name">{name}</div>
                <div className="item-price">&#x20B9;{price}</div>
              </div>
            </div>
          );
        })}
        {items.length === 0 && (
          <div style={{ color: '#666', padding: '20px', textAlign: 'center', width: '100%' }}>
            No items in this category yet.
          </div>
        )}
      </div>
    </>
  );
});

// ==========================================
// BILL ACTIVE ORDER PANEL COMPONENT
// ==========================================
function useClock() {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return now;
}

function LiveClock() {
  const now = useClock();
  return (
    <div className="datetime">
      <span>Date: {now.toLocaleDateString()}</span>
      <span>Time: {now.toLocaleTimeString()}</span>
    </div>
  );
}

const BillPanel = React.memo(function BillPanel({
  cart, total, billNumber, paymentMethod, orderType,
  onPaymentChange, onOrderTypeChange,
  onIncrease, onDecrease, onRemove,
  onPrint, onClear, isPrinting
}) {
  const cartEntries = Object.entries(cart);
  const hasItems = cartEntries.length > 0;

  return (
    <div className="bill">
      <div className="cut-line" />

      <div className="bill-header">
        <div className="bill-number">
          Bill No: <span id="billNoDisplay">{billNumber}</span>
        </div>
        <b>Sri Vengamamba Food Court</b><br />
        <span className="bill-subtitle">Chinese Kitchen / Juice Bar</span>
        <LiveClock />
      </div>

      <div className="bill-items">
        <table id="billTable">
          <thead>
            <tr>
              <th>Item</th>
              <th>Qty</th>
              <th>Price</th>
              <th>Remove</th>
            </tr>
          </thead>
          <tbody>
            {!hasItems ? (
              <tr><td colSpan="4" className="empty-bill">No items added yet</td></tr>
            ) : (
              cartEntries.map(([name, item]) => (
                <tr key={name}>
                  <td>{name}</td>
                  <td className="qty-cell">
                    <div className="qty-controls">
                      <button className="qty-btn" onClick={() => onDecrease(name)}>−</button>
                      <span className="qty-display">{item.qty}</span>
                      <button className="qty-btn" onClick={() => onIncrease(name)}>+</button>
                    </div>
                  </td>
                  <td>₹{item.price * item.qty}</td>
                  <td className="remove-cell">
                    <button className="remove-btn" onClick={() => onRemove(name)}>✕</button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="payment-options">
        <label>Payment Method:</label>
        <span className="print-value"> {paymentMethod}</span>
        <CustomSelect 
          className="screen-only" 
          value={paymentMethod} 
          onChange={e => onPaymentChange(e.target.value)}
          options={[
            {value: "UPI", label: "UPI"},
            {value: "Cash", label: "Cash"},
            {value: "Cash / UPI", label: "Cash / UPI"},
            {value: "Card", label: "Card"}
          ]}
        />
      </div>

      <div className="payment-options">
        <label>Order Type:</label>
        <span className="print-value"> {orderType}</span>
        <CustomSelect 
          className="screen-only" 
          value={orderType} 
          onChange={e => onOrderTypeChange(e.target.value)}
          options={[
            {value: "Dine-in / Take Out", label: "Dine-in / Take Out"},
            {value: "Swiggy / Zomato", label: "Swiggy / Zomato"},
            {value: "Dine-in", label: "Dine-in"},
            {value: "Take Out", label: "Take Out"},
            {value: "Zomato", label: "Zomato"},
            {value: "Swiggy", label: "Swiggy"}
          ]}
        />
      </div>

      <div className="total-section">
        <div className="total">Total: ₹<span id="total">{total}</span></div>
      </div>

      <div className="actions">
        <button
          id="printBtn"
          className="print"
          onClick={onPrint}
          disabled={isPrinting || !hasItems || total === 0}
        >
          {isPrinting ? 'Saving...' : 'Print'}
        </button>
        <button
          id="clearBtn"
          className="clear"
          onClick={onClear}
          disabled={!hasItems}
        >
          Clear
        </button>
      </div>

      <div className="footer" style={{ marginTop: '4px' }}>
        <div style={{ fontSize: '12px', marginBottom: '2px' }}>Thank you!</div>
        <b>© ANITS 2023–2027 CSE 88 DEV</b>
      </div>

      <div className="cut-line thermal-cut" />
    </div>
  );
});

// ==========================================
// MODAL COMPONENTS
// ==========================================

function PrintClearModal({ onOk }) {
  return (
    <div className="modal-overlay">
      <div className="modal-content print-clear-modal-content">
        <div className="modal-header">
          <h2>Bill Printed</h2>
        </div>
        <p className="print-clear-message">Click OK to clear previous items and reset the bill panel for the next order.</p>
        <div className="modal-actions">
          <button type="button" className="btn-add" onClick={onOk} autoFocus>OK</button>
        </div>
      </div>
    </div>
  );
}

function CustomItemModal({ onClose, onAdd, showPopup }) {
  const [name, setName] = useState('');
  const [price, setPrice] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    const p = parseInt(price);
    if (name.trim() && p > 0) {
      onAdd(name.trim(), p);
      onClose();
    }
  };

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal-content">
        <div className="modal-header">
          <h2>Add Custom Item</h2>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Item Name *</label>
            <input type="text" value={name} onChange={e => setName(e.target.value)} placeholder="e.g., Special Thali" required autoFocus />
          </div>
          <div className="form-group">
            <label>Price (₹) *</label>
            <input type="number" value={price} onChange={e => setPrice(e.target.value)} placeholder="e.g., 150" min="1" required />
          </div>
          <div className="modal-actions">
            <button type="button" className="btn-cancel" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn-add">Add to Bill</button>
          </div>
        </form>
      </div>
    </div>
  );
}

function AddCategoryModal({ onClose, showPopup, onAdded }) {
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const catName = name.trim();
    if (!catName) { alert('Please enter a valid category name.'); return; }
    setLoading(true);
    try {
      const res = await fetch(apiUrl('/api/custom-categories'), {
        method: 'POST', headers: getAuthHeaders(),
        body: JSON.stringify({ name: catName })
      });
      const result = await res.json();
      if (!res.ok || !result.success) {
        showPopup(result.error || 'Failed to add category', 'danger');
        setLoading(false);
        return;
      }
      onClose();
      onAdded(catName);
      showPopup(`Category "${catName}" added successfully.`, 'gold');
    } catch {
      showPopup('Failed to add category. Please try again.', 'danger');
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && !loading && onClose()}>
      <div className="modal-content category-modal-content">
        <div className="modal-header">
          <h2>Add New Category</h2>
          <button className="modal-close" onClick={onClose} disabled={loading}>×</button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Category Name *</label>
            <input type="text" value={name} onChange={e => setName(e.target.value)} placeholder="e.g., Desserts" required autoFocus disabled={loading} />
          </div>
          <div className="modal-actions">
            <button type="button" className="btn-cancel" onClick={onClose} disabled={loading}>Cancel</button>
            <button type="submit" className="btn-add" disabled={loading}>
              {loading ? 'Adding...' : 'Add Category'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

const AddMenuItemModal = React.memo(function AddMenuItemModal({ onClose, showPopup, customCategories, onRefresh }) {
  const [name, setName] = useState('');
  const [price, setPrice] = useState('');
  const [category, setCategory] = useState('');
  const [imageUrl, setImageUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const allCategories = Array.from(new Set(['Tiffins','Meals','Biryanis','Starters','Fast Food','Juice Bar', ...customCategories]));

  useEffect(() => { if (allCategories.length > 0) setCategory(allCategories[0]); }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const p = parseFloat(price);
    if (!name.trim() || !p || p <= 0) { showPopup('Please enter valid name and price', 'danger'); return; }
    setLoading(true);
    try {
      const res = await fetch(apiUrl('/api/custom-items'), {
        method: 'POST', headers: getAuthHeaders(),
        body: JSON.stringify({ name: name.trim(), price: p, category: category || 'Custom', imageUrl: imageUrl.trim() })
      });
      const data = await res.json();
      if (data.success) {
        onClose();
        onRefresh(category || 'Custom');
        showPopup(`"${name.trim()}" added to menu!`, 'gold');
      } else {
        showPopup(data.error || 'Failed to add item', 'danger');
        setLoading(false);
      }
    } catch {
      showPopup('Failed to add item to menu', 'danger');
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && !loading && onClose()}>
      <div className="modal-content menu-modal-content">
        <div className="modal-header">
          <h2>Add Menu Item</h2>
          <button className="modal-close" onClick={onClose} disabled={loading}>×</button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="add-menu-split">
            <div className="add-menu-left">
              <div className="form-group">
                <label>Item Name *</label>
                <input type="text" value={name} onChange={e => setName(e.target.value)} placeholder="e.g., Special Manchurian" required autoFocus disabled={loading} />
              </div>
              <div className="form-group">
                <label>Price (₹) *</label>
                <input type="number" value={price} onChange={e => setPrice(e.target.value)} placeholder="e.g., 150" min="1" required disabled={loading} />
              </div>
              <div className="form-group">
                <label>Category *</label>
                <CustomSelect 
                  value={category} 
                  onChange={e => setCategory(e.target.value)} 
                  disabled={loading}
                  options={allCategories.map(c => ({value: c, label: c}))}
                />
              </div>
            </div>
            
            <div className="add-menu-right">
              <div className="form-group" style={{ marginBottom: '15px' }}>
                <label>Image URL (Optional)</label>
                <input type="url" value={imageUrl} onChange={e => setImageUrl(e.target.value)} placeholder="https://example.com/image.jpg" disabled={loading} />
                <div className="field-note" style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>Paste a full image URL</div>
              </div>
              
              <label className="preview-label">Live Preview</label>
              <div 
                className="menu-item" 
                style={{
                  pointerEvents: 'none', 
                  margin: 0, 
                  width: '100%', 
                  cursor: 'default',
                  aspectRatio: '4/3',
                  backgroundImage: imageUrl ? `url(${imageUrl})` : 'none',
                  backgroundSize: 'cover',
                  backgroundPosition: 'center',
                  backgroundRepeat: 'no-repeat'
                }}
              >
                {!imageUrl && (
                  <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', opacity: 0.3 }}>
                    <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
                  </div>
                )}
                <div className="menu-item-info">
                  <div className="item-name">{name || 'Item Name'}</div>
                  <div className="item-price">&#x20B9;{parseFloat(price) > 0 ? parseFloat(price) : 0}</div>
                </div>
              </div>
            </div>
          </div>
          <div className="modal-actions">
            <button type="button" className="btn-cancel" onClick={onClose} disabled={loading}>Cancel</button>
            <button type="submit" className="btn-add" disabled={loading}>
              {loading ? 'Adding...' : 'Add to Menu'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
});

const DeleteCategoryModal = React.memo(function DeleteCategoryModal({ onClose, showPopup, customCategories, onRefresh }) {
  const [selected, setSelected] = useState(new Set());
  const [loading, setLoading] = useState(false);

  const toggle = (cat) => setSelected(prev => {
    const next = new Set(prev);
    next.has(cat) ? next.delete(cat) : next.add(cat);
    return next;
  });

  const setAll = (checked) => {
    setSelected(checked ? new Set(customCategories) : new Set());
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const cats = Array.from(selected);
    if (!cats.length) { alert('Please select at least one category to delete.'); return; }
    const token = localStorage.getItem('authToken') || localStorage.getItem('token');
    setLoading(true);
    try {
      const promises = cats.map(async (cat) => {
        try {
          const res = await fetch(apiUrl(`/api/custom-categories/${encodeURIComponent(cat)}`), {
            method: 'DELETE', headers: { 'Authorization': `Bearer ${token}` }
          });
          const result = await res.json();
          return { cat, success: res.ok && result.success, error: result.error || 'Failed' };
        } catch (err) {
          return { cat, success: false, error: err.message };
        }
      });
      const results = await Promise.all(promises);
      const failed = [], deleted = [];
      for (const r of results) {
        if (r.success) deleted.push(r.cat);
        else failed.push(`${r.cat}: ${r.error}`);
      }
      if (deleted.length) {
        onClose();
        onRefresh();
      } else {
        setLoading(false);
      }
      if (failed.length && !deleted.length) {
        showPopup(failed.join(' | '), 'danger');
        return;
      }
      if (failed.length) {
        showPopup(`Deleted ${deleted.length}. Some failed: ${failed.join(' | ')}`, 'gold');
      } else {
        showPopup(`Deleted ${deleted.length} categor${deleted.length === 1 ? 'y' : 'ies'} successfully.`, 'gold');
      }
    } catch {
      showPopup('Failed to delete categories. Please try again.', 'danger');
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && !loading && onClose()}>
      <div className="modal-content category-modal-content">
        <div className="modal-header">
          <h2>Delete Category</h2>
          <button className="modal-close" onClick={onClose} disabled={loading}>×</button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Select Categories to Delete *</label>
            <div className="delete-category-toolbar">
              <button type="button" className="delete-category-toolbar-btn" onClick={() => setAll(true)} disabled={loading}>Select All</button>
              <button type="button" className="delete-category-toolbar-btn secondary" onClick={() => setAll(false)} disabled={loading}>Clear</button>
              <div className="delete-category-count">{selected.size} selected</div>
            </div>
            <div className="delete-category-list">
              {customCategories.length === 0
                ? <div className="delete-category-empty">No custom categories available to delete.</div>
                : customCategories.map(cat => (
                  <label key={cat} className="delete-category-item">
                    <input type="checkbox" checked={selected.has(cat)} onChange={() => toggle(cat)} disabled={loading} />
                    <span>{cat}</span>
                  </label>
                ))
              }
            </div>
          </div>
          <div className="modal-actions">
            <button type="button" className="btn-cancel" onClick={onClose} disabled={loading}>Cancel</button>
            <button type="submit" className="btn-delete" disabled={loading}>
              {loading ? 'Deleting...' : 'Delete Selected'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
});

const DeleteMenuModal = React.memo(function DeleteMenuModal({ onClose, showPopup, customItemIndex, onRefresh }) {
  const categories = useMemo(() => {
    return Array.from(new Set(customItemIndex.map(i => (i.category || 'Custom').trim()))).sort();
  }, [customItemIndex]);

  const [activeCategory, setActiveCategory] = useState(categories[0] || '');
  const [selected, setSelected] = useState(new Set());
  const [loading, setLoading] = useState(false);

  const filteredItems = useMemo(() =>
    customItemIndex.filter(i => (i.category || 'Custom').trim() === activeCategory).sort((a,b) => a.name.localeCompare(b.name)),
    [customItemIndex, activeCategory]
  );

  useEffect(() => {
    if (categories.length > 0 && !categories.includes(activeCategory)) {
      setActiveCategory(categories[0]);
    }
  }, [categories]);

  const toggleItem = (name) => setSelected(prev => {
    const next = new Set(prev); next.has(name) ? next.delete(name) : next.add(name); return next;
  });

  const setAll = (checked) => setSelected(checked ? new Set(filteredItems.map(i => i.name)) : new Set());

  const handleCategoryChange = (cat) => { if (!loading) { setActiveCategory(cat); setSelected(new Set()); } };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const items = Array.from(selected);
    if (!items.length) { showPopup('Please select at least one item to delete.', 'danger'); return; }
    const token = localStorage.getItem('authToken') || localStorage.getItem('token');
    setLoading(true);
    try {
      const promises = items.map(async (name) => {
        try {
          const res = await fetch(apiUrl(`/api/custom-items/${encodeURIComponent(name)}`), {
            method: 'DELETE', headers: { 'Authorization': `Bearer ${token}` }
          });
          const result = await res.json();
          return { name, success: res.ok && result.success, error: result.error || 'Failed' };
        } catch (err) {
          return { name, success: false, error: err.message };
        }
      });
      const results = await Promise.all(promises);
      const failed = [], deleted = [];
      for (const r of results) {
        if (r.success) deleted.push(r.name);
        else failed.push(`${r.name}: ${r.error}`);
      }
      if (deleted.length) {
        onClose();
        onRefresh();
      } else {
        setLoading(false);
      }
      if (failed.length && !deleted.length) {
        showPopup(failed.join(' | '), 'danger');
        return;
      }
      if (failed.length) {
        showPopup(`Deleted ${deleted.length}. Some failed: ${failed.join(' | ')}`, 'gold');
      } else {
        showPopup(`Deleted ${deleted.length} item${deleted.length === 1 ? '' : 's'} successfully.`, 'gold');
      }
    } catch {
      showPopup('Failed to delete menu items. Please try again.', 'danger');
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && !loading && onClose()}>
      <div className="modal-content edit-menu-modal-content">
        <div className="modal-header">
          <h2>Delete Menu Item</h2>
          <button className="modal-close" onClick={onClose} disabled={loading}>×</button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="edit-menu-layout">
            <div className="edit-menu-sidebar">
              <div className="edit-menu-sidebar-title">Categories</div>
              <div className="edit-menu-category-list">
                {categories.length === 0
                  ? <div className="delete-menu-empty-note">No categories yet.</div>
                  : categories.map(cat => (
                    <button key={cat} type="button" className={`edit-menu-sidebar-btn ${cat === activeCategory ? 'active' : ''}`}
                      onClick={() => handleCategoryChange(cat)} disabled={loading}>{cat}</button>
                  ))
                }
              </div>
            </div>
            
            <div className="edit-menu-main">
              <div className="form-group">
                <label>Select Items from Category *</label>
                <div className="delete-menu-toolbar">
                  <button type="button" className="delete-menu-toolbar-btn" onClick={() => setAll(true)} disabled={loading}>Select All</button>
                  <button type="button" className="delete-menu-toolbar-btn secondary" onClick={() => setAll(false)} disabled={loading}>Clear</button>
                  <div className="delete-menu-count">{selected.size} selected</div>
                </div>
                <div className="delete-menu-grid">
                  {filteredItems.length === 0
                    ? <div className="delete-menu-empty-note">No items found in this category.</div>
                    : filteredItems.map(item => (
                      <div 
                        key={item.name} 
                        className={`menu-item delete-card-item ${selected.has(item.name) ? 'selected' : ''}`}
                        style={{
                          ...(item.imageUrl ? { backgroundImage: `url('${item.imageUrl}')`, backgroundSize: 'cover', backgroundPosition: 'center' } : {}),
                          aspectRatio: '4/3',
                          minHeight: '110px'
                        }}
                        onClick={() => !loading && toggleItem(item.name)}
                      >
                        {!item.imageUrl && (
                          <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', opacity: 0.3 }}>
                            <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
                          </div>
                        )}
                        <div className="menu-item-info">
                          <div className="item-name">{item.name}</div>
                          <div className="item-price">&#x20B9;{item.price || 0}</div>
                        </div>
                        {selected.has(item.name) && (
                          <div className="delete-card-overlay">
                            <div className="delete-card-checkmark">✓</div>
                          </div>
                        )}
                      </div>
                    ))
                  }
                </div>
              </div>
            </div>
          </div>
          <div className="modal-actions" style={{ marginTop: '15px', paddingTop: '15px' }}>
            <button type="button" className="btn-cancel" onClick={onClose} disabled={loading}>Cancel</button>
            <button type="submit" className="btn-delete" disabled={loading}>
              {loading ? 'Deleting...' : 'Delete Selected'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
});

const EditMenuModal = React.memo(function EditMenuModal({ onClose, showPopup, customItemIndex, customCategories, menuData, onRefresh }) {
  const categories = useMemo(() => {
    return Array.from(new Set(customItemIndex.map(i => (i.category || 'Custom').trim()))).sort();
  }, [customItemIndex]);

  const allCategories = useMemo(() => {
    const s = new Set([...Object.keys(menuData || {}), ...customCategories, ...customItemIndex.map(i => (i.category || 'Custom').trim())]);
    return Array.from(s).filter(Boolean).sort();
  }, [menuData, customCategories, customItemIndex]);

  const [activeCategory, setActiveCategory] = useState(categories[0] || '');
  const [selectedName, setSelectedName] = useState('');
  const [editName, setEditName] = useState('');
  const [editPrice, setEditPrice] = useState('');
  const [editCategory, setEditCategory] = useState('');
  const [editImageUrl, setEditImageUrl] = useState('');
  const [originalName, setOriginalName] = useState('');
  const [imgError, setImgError] = useState(false);
  const [loading, setLoading] = useState(false);

  const filteredItems = useMemo(() =>
    customItemIndex.filter(i => (i.category || 'Custom').trim() === activeCategory).sort((a,b) => a.name.localeCompare(b.name)),
    [customItemIndex, activeCategory]
  );

  useEffect(() => {
    if (categories.length > 0 && !categories.includes(activeCategory)) {
      setActiveCategory(categories[0]);
    }
  }, [categories]);

  useEffect(() => {
    if (filteredItems.length > 0) fillForm(filteredItems[0]);
    else clearForm();
  }, [activeCategory, filteredItems]);

  const fillForm = (item) => {
    setSelectedName(item.name); setOriginalName(item.name);
    setEditName(item.name); setEditPrice(item.price.toString());
    setEditCategory(item.category || 'Custom'); setEditImageUrl(item.imageUrl || '');
    setImgError(false);
  };
  const clearForm = () => {
    setSelectedName(''); setOriginalName(''); setEditName(''); setEditPrice('');
    setEditCategory(allCategories[0] || ''); setEditImageUrl(''); setImgError(false);
  };

  const handleCategoryChange = (cat) => { if (!loading) setActiveCategory(cat); };
  const handleItemSelect = (e) => {
    const item = customItemIndex.find(i => i.name === e.target.value);
    if (item) fillForm(item); else clearForm();
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!originalName) { showPopup('Please select an item to edit.', 'danger'); return; }
    const newName = editName.trim();
    const newPrice = parseFloat(editPrice);
    const newCat = editCategory.trim();
    const newImg = editImageUrl.trim();
    if (!newName) { showPopup('Item name is required.', 'danger'); return; }
    if (!Number.isFinite(newPrice) || newPrice <= 0) { showPopup('Price must be a valid positive number.', 'danger'); return; }
    if (!newCat) { showPopup('Please select a valid category.', 'danger'); return; }
    setLoading(true);
    try {
      const res = await fetch(apiUrl(`/api/custom-items/${encodeURIComponent(originalName)}`), {
        method: 'PUT', headers: getAuthHeaders(),
        body: JSON.stringify({ name: newName, price: newPrice, category: newCat, imageUrl: newImg })
      });
      const result = await res.json();
      if (!res.ok || !result.success) {
        showPopup(result.error || 'Failed to update menu item.', 'danger');
        setLoading(false);
        return;
      }
      onClose();
      onRefresh(newCat);
      showPopup(`"${newName}" updated successfully.`, 'gold');
    } catch {
      showPopup('Failed to update menu item. Please try again.', 'danger');
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && !loading && onClose()}>
      <div className="modal-content edit-menu-modal-content">
        <div className="modal-header">
          <h2>Edit Menu Item</h2>
          <button className="modal-close" onClick={onClose} disabled={loading}>×</button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="edit-menu-layout">
            <div className="edit-menu-sidebar">
              <div className="edit-menu-sidebar-title">Categories</div>
              <div className="edit-menu-category-list">
                {categories.length === 0
                  ? <div className="delete-menu-empty-note">No categories yet.</div>
                  : categories.map(cat => (
                    <button key={cat} type="button" className={`edit-menu-sidebar-btn ${cat === activeCategory ? 'active' : ''}`}
                      onClick={() => handleCategoryChange(cat)} disabled={loading}>{cat}</button>
                  ))
                }
              </div>
            </div>
            
            <div className="edit-menu-main">
              <div className="add-menu-split" style={{ marginBottom: 0 }}>
                <div className="add-menu-left">
                  <div className="form-group">
                    <label>Select Item to Edit *</label>
                    <CustomSelect 
                      value={selectedName} 
                      onChange={handleItemSelect} 
                      disabled={loading}
                      placeholder="-- Select Item --"
                      options={filteredItems.map(i => ({value: i.name, label: i.name}))}
                    />
                  </div>
                  <div className="form-group">
                    <label>Item Name *</label>
                    <input type="text" value={editName} onChange={e => setEditName(e.target.value)} placeholder="Item name" required disabled={loading} />
                  </div>
                  <div className="form-group">
                    <label>Price (₹) *</label>
                    <input type="number" value={editPrice} onChange={e => setEditPrice(e.target.value)} placeholder="e.g., 120" min="1" step="0.01" required disabled={loading} />
                  </div>
                  <div className="form-group">
                    <label>Category *</label>
                    <CustomSelect 
                      value={editCategory} 
                      onChange={e => setEditCategory(e.target.value)} 
                      disabled={loading}
                      options={allCategories.map(c => ({value: c, label: c}))}
                    />
                  </div>
                </div>
                
                <div className="add-menu-right">
                  <div className="form-group" style={{ marginBottom: '15px' }}>
                    <label>Image URL (Optional)</label>
                    <input type="url" value={editImageUrl} onChange={e => { setEditImageUrl(e.target.value); setImgError(false); }} placeholder="https://example.com/image.jpg" disabled={loading} />
                  </div>
                  
                  <label className="preview-label">Live Preview</label>
                  <div 
                    className="menu-item" 
                    style={{
                      pointerEvents: 'none', 
                      margin: 0, 
                      width: '100%', 
                      cursor: 'default',
                      aspectRatio: '4/3',
                      backgroundImage: editImageUrl && !imgError ? `url(${editImageUrl})` : 'none',
                      backgroundSize: 'cover',
                      backgroundPosition: 'center',
                      backgroundRepeat: 'no-repeat'
                    }}
                  >
                    {(!editImageUrl || imgError) && (
                      <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', opacity: 0.3 }}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
                      </div>
                    )}
                    <div className="menu-item-info">
                      <div className="item-name">{editName || 'Item Name'}</div>
                      <div className="item-price">&#x20B9;{parseFloat(editPrice) > 0 ? parseFloat(editPrice) : 0}</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="modal-actions" style={{ marginTop: '15px', paddingTop: '15px' }}>
            <button type="button" className="btn-cancel" onClick={onClose} disabled={loading}>Cancel</button>
            <button type="submit" className="btn-add" disabled={loading}>
              {loading ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
});


// ==========================================
// CUSTOM COMPONENTS
// ==========================================

function CustomDatePicker({ value, onChange, className }) {
  const [isOpen, setIsOpen] = useState(false);
  const [placement, setPlacement] = useState('bottom');
  const [popupStyle, setPopupStyle] = useState({});
  const [currentMonth, setCurrentMonth] = useState(() => {
    return value ? new Date(value) : new Date();
  });
  const wrapperRef = useRef(null);
  const popupRef = useRef(null);

  useEffect(() => {
    if (value) setCurrentMonth(new Date(value));
  }, [value]);

  useEffect(() => {
    const handleClickOutside = (e) => {
      if (wrapperRef.current && wrapperRef.current.contains(e.target)) return;
      if (popupRef.current && popupRef.current.contains(e.target)) return;
      setIsOpen(false);
    };
    
    const handleScroll = () => {
      if (isOpen) setIsOpen(false);
    };

    document.addEventListener('mousedown', handleClickOutside);
    window.addEventListener('scroll', handleScroll, true);
    window.addEventListener('resize', handleScroll);
    
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      window.removeEventListener('scroll', handleScroll, true);
      window.removeEventListener('resize', handleScroll);
    };
  }, [isOpen]);

  React.useLayoutEffect(() => {
    if (isOpen && wrapperRef.current) {
      const rect = wrapperRef.current.getBoundingClientRect();
      const popupHeight = 340; // Approx height of the calendar
      const popupWidth = 280;
      
      let newStyle = {
        position: 'fixed',
        width: popupWidth,
        zIndex: 99999,
      };

      // Prioritize popping to the right
      if (rect.right + popupWidth + 10 <= window.innerWidth) {
        newStyle.left = rect.right + 10;
        setPlacement('right');
      } 
      // If no room on right, try left
      else if (rect.left - popupWidth - 10 >= 0) {
        newStyle.left = rect.left - popupWidth - 10;
        setPlacement('left');
      } 
      // If neither fits (e.g. mobile), fallback to bottom/top
      else {
        newStyle.left = rect.left;
        if (rect.bottom + popupHeight > window.innerHeight && rect.top - popupHeight > 0) {
          newStyle.bottom = window.innerHeight - rect.top + 8;
          newStyle.top = 'auto';
          setPlacement('top');
        } else {
          newStyle.top = rect.bottom + 8;
          newStyle.bottom = 'auto';
          setPlacement('bottom');
        }
      }

      // If placed on left or right, adjust vertical position so it doesn't go off-screen
      if (placement === 'right' || placement === 'left' || newStyle.left !== rect.left) {
        if (rect.top + popupHeight > window.innerHeight) {
          // If aligning tops pushes it off the bottom, anchor it to the bottom of the screen
          newStyle.bottom = 20;
          newStyle.top = 'auto';
        } else {
          // Otherwise align the top of the popup with the top of the input
          newStyle.top = rect.top;
          newStyle.bottom = 'auto';
        }
      }

      setPopupStyle(newStyle);
    }
  }, [isOpen, placement]);

  const getDaysInMonth = (year, month) => new Date(year, month + 1, 0).getDate();
  const getFirstDayOfMonth = (year, month) => new Date(year, month, 1).getDay();

  const year = currentMonth.getFullYear();
  const month = currentMonth.getMonth();
  const daysInMonth = getDaysInMonth(year, month);
  const firstDay = getFirstDayOfMonth(year, month);

  const monthNames = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
  const dayNames = ["Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"];

  const handlePrevMonth = () => setCurrentMonth(new Date(year, month - 1, 1));
  const handleNextMonth = () => setCurrentMonth(new Date(year, month + 1, 1));

  const handleDateClick = (day) => {
    const selectedDate = new Date(year, month, day);
    const yyyy = selectedDate.getFullYear();
    const mm = String(selectedDate.getMonth() + 1).padStart(2, '0');
    const dd = String(selectedDate.getDate()).padStart(2, '0');
    onChange(`${yyyy}-${mm}-${dd}`);
    setIsOpen(false);
  };

  const handleTodayClick = () => {
    const today = new Date();
    const yyyy = today.getFullYear();
    const mm = String(today.getMonth() + 1).padStart(2, '0');
    const dd = String(today.getDate()).padStart(2, '0');
    onChange(`${yyyy}-${mm}-${dd}`);
    setIsOpen(false);
  };

  const handleClear = () => {
    onChange('');
    setIsOpen(false);
  };

  const selectedDateObj = value ? new Date(value) : null;

  return (
    <div className="custom-date-picker-wrapper" ref={wrapperRef}>
      <div 
        className={`custom-date-picker-input ${isOpen ? 'active' : ''} ${className || ''}`} 
        onClick={() => setIsOpen(!isOpen)}
      >
        <span>{value || 'Select Date...'}</span>
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
      </div>
      
      {isOpen && ReactDOM.createPortal(
        <div className={`custom-date-picker-popup placement-${placement}`} style={popupStyle} ref={popupRef}>
          <div className="calendar-header">
            <span className="calendar-month-year">{monthNames[month]} {year}</span>
            <div className="calendar-nav">
              <button onClick={handlePrevMonth} type="button">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="15 18 9 12 15 6"></polyline></svg>
              </button>
              <button onClick={handleNextMonth} type="button">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="9 18 15 12 9 6"></polyline></svg>
              </button>
            </div>
          </div>
          
          <div className="calendar-grid">
            {dayNames.map(day => <div key={day} className="calendar-day-name">{day}</div>)}
            
            {Array.from({ length: firstDay }).map((_, i) => (
              <div key={`empty-${i}`} className="calendar-day empty"></div>
            ))}
            
            {Array.from({ length: daysInMonth }).map((_, i) => {
              const day = i + 1;
              const isSelected = selectedDateObj && selectedDateObj.getDate() === day && selectedDateObj.getMonth() === month && selectedDateObj.getFullYear() === year;
              return (
                <div 
                  key={day} 
                  className={`calendar-day ${isSelected ? 'selected' : ''}`}
                  onClick={() => handleDateClick(day)}
                >
                  {day}
                </div>
              );
            })}
          </div>
          <div className="calendar-footer">
            <button type="button" onClick={handleClear} className="calendar-btn calendar-clear-btn">Clear</button>
            <button type="button" onClick={handleTodayClick} className="calendar-btn calendar-today-btn">Today</button>
          </div>
        </div>
      , document.body)}
    </div>
  );
}
function CustomSelect({ options, value, onChange, placeholder, className, disabled }) {
  const [open, setOpen] = useState(false);
  const [dropdownStyle, setDropdownStyle] = useState({});
  const ref = useRef(null);

  useEffect(() => {
    const handler = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('click', handler);
    return () => document.removeEventListener('click', handler);
  }, [open]);

  const handleToggle = () => {
    if (disabled) return;
    if (!open && ref.current) {
      const rect = ref.current.getBoundingClientRect();
      const spaceBelow = window.innerHeight - rect.bottom;
      const spaceAbove = rect.top;
      const dropdownHeight = 250; 
      let top, bottom;
      
      if (spaceBelow < dropdownHeight && spaceAbove > spaceBelow) {
        bottom = window.innerHeight - rect.top + 5;
      } else {
        top = rect.bottom + 5;
      }
      
      setDropdownStyle({
        position: 'fixed',
        left: rect.left,
        width: rect.width,
        top: top !== undefined ? top : 'auto',
        bottom: bottom !== undefined ? bottom : 'auto',
        maxHeight: '250px',
        overflowY: 'auto',
        zIndex: 999999
      });
    }
    setOpen(!open);
  };

  const selectedOption = options.find(o => o.value === value);

  return (
    <div className={`custom-select-container ${className || ''} ${disabled ? 'disabled' : ''}`} ref={ref}>
      <div className={`custom-select-trigger ${open ? 'open' : ''} ${!value ? 'placeholder' : ''}`} onClick={handleToggle}>
        {selectedOption ? selectedOption.label : placeholder}
        <span className="chevron">▼</span>
      </div>
      {open && !disabled && (
        <div className="custom-select-dropdown" style={dropdownStyle}>
          {options.map(opt => (
            <div 
              key={opt.value} 
              className={`custom-select-option ${value === opt.value ? 'selected' : ''}`}
              onClick={() => { onChange({ target: { value: opt.value } }); setOpen(false); }}
            >
              {opt.label}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function CustomInstallModal({ onClose, onConfirm }) {
  return (
    <div className="modal-overlay install-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal-content install-modal-content">
        <div className="install-modal-header">
          <img src="/static/app_icon.png" alt="Logo" className="install-modal-logo" onError={(e)=>{e.target.style.display='none'}}/>
          <div className="install-modal-title-group">
            <h2>Sri Vengamamba Food Court</h2>
            <p>Billing Portal App</p>
          </div>
        </div>
        <p className="install-modal-desc">Install our application on your device for quick access, offline capabilities, and a better full-screen experience.</p>
        <div className="modal-actions install-modal-actions">
          <button type="button" className="btn-cancel" onClick={onClose}>Not Now</button>
          <button type="button" className="btn-add install-btn-confirm" onClick={onConfirm}>Install App</button>
        </div>
      </div>
    </div>
  );
}

function LoginPage({ onLoginSuccess }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [installPrompt, setInstallPrompt] = useState(null);
  const [installable, setInstallable] = useState(false);
  const [installDone, setInstallDone] = useState(false);
  const [showCustomInstall, setShowCustomInstall] = useState(false);

  useEffect(() => {
    const handler = (e) => {
      e.preventDefault();
      setInstallPrompt(e);
      setInstallable(true);
    };
    window.addEventListener('beforeinstallprompt', handler);
    window.addEventListener('appinstalled', () => { setInstallDone(true); setInstallable(false); });
    return () => window.removeEventListener('beforeinstallprompt', handler);
  }, []);

  const handleInstallClick = () => {
    if (!installPrompt) return;
    setShowCustomInstall(true);
  };

  const handleInstallConfirm = async () => {
    setShowCustomInstall(false);
    if (!installPrompt) return;
    installPrompt.prompt();
    const { outcome } = await installPrompt.userChoice;
    if (outcome === 'accepted') { setInstallDone(true); setInstallable(false); }
    setInstallPrompt(null);
  };

  useEffect(() => {
    if (localStorage.getItem('authToken')) {
      window.location.hash = '#/';
    }
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(''); setSuccess('');
    if (!email || !password) { setError('Please fill in all fields'); return; }
    setLoading(true);
    try {
      const res = await fetch(apiUrl('/api/auth/login'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      if (data.success) {
        setSuccess('Login successful! Redirecting...');
        localStorage.setItem('authToken', data.token);
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        setTimeout(() => {
          onLoginSuccess();
          window.location.hash = '#/';
        }, 900);
      } else {
        setError(data.error || 'Login failed');
        setLoading(false);
      }
    } catch (err) {
      setError('Network error: ' + err.message);
      setLoading(false);
    }
  };

  return (
    <div className="page-shell">
      <header className="login-header-bar">
        <div className="login-header-inner">
          <div className="login-header-spacer" />
          <div className="login-header-titles">
            <h1>Sri Vengamamba Food Court</h1>
            <h3>Chinese Kitchen / Fruit Bar</h3>
          </div>
          <div className="login-header-actions">
            {!installDone && installable && (
              <button className="pwa-install-btn" onClick={handleInstallClick} title="Install App on Mobile">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="5" y="2" width="14" height="20" rx="2" ry="2"/>
                  <line x1="12" y1="7" x2="12" y2="13"/>
                  <polyline points="9 10 12 13 15 10"/>
                  <line x1="9" y1="17" x2="15" y2="17"/>
                </svg>
                <span>Install App</span>
              </button>
            )}
            {installDone && (
              <div className="pwa-installed-badge">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="20 6 9 17 4 12"/>
                </svg>
                Installed!
              </div>
            )}
          </div>
        </div>
      </header>

      <div className="login-container">
        {showCustomInstall && <CustomInstallModal onClose={() => setShowCustomInstall(false)} onConfirm={handleInstallConfirm} />}
        <div className="login-box">
          <div className="login-title-section">
            <h1>Login</h1>
          </div>

          {error && <div className="error-message show">{error}</div>}
          {success && <div className="success-message show">{success}</div>}

          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label htmlFor="email">Account</label>
              <CustomSelect
              placeholder="Select account"
              value={email}
              onChange={e => { setEmail(e.target.value); setError(''); setSuccess(''); }}
              options={[
                { value: 'admin@svfc.com', label: 'Admin' },
                { value: 'casher1@svfc.com', label: 'Casher 1' },
                { value: 'casher2@svfc.com', label: 'Casher 2' }
              ]}
            />
            </div>

            <div className="form-group">
              <label htmlFor="password">Password</label>
              <div className="password-field">
                <input
                  type={showPassword ? 'text' : 'password'}
                  id="password"
                  value={password}
                  onChange={e => { setPassword(e.target.value); setError(''); setSuccess(''); }}
                  placeholder="Enter your password"
                  required
                />
                <button
                  type="button"
                  className="toggle-password"
                  onClick={() => setShowPassword(v => !v)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  
                  {showPassword ? (
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
                  ) : (
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                  )}
    
                </button>
              </div>
            </div>

            <button type="submit" className="login-btn" disabled={loading}>
              {loading ? 'Logging in...' : 'Login'}
              {loading && <span className="loading-spinner show" />}
            </button>
          </form>
        </div>
      </div>

      <div className="login-footer">
        <b>© ANITS 2023–2027 CSE 88 DEV</b>
      </div>
    </div>
  );
}

// ==========================================
// PAGE COMPONENT: POS POINT OF SALE
// ==========================================
const DRAFT_KEY = 'svfcDraftBill_v2';

function POSPage() {
  const [menuData, setMenuData] = useState({});
  const [customCategories, setCustomCategories] = useState([]);
  const [customItemIndex, setCustomItemIndex] = useState([]);
  const [cart, setCart] = useState({});
  const [billNumber, setBillNumber] = useState(0);
  const [paymentMethod, setPaymentMethod] = useState('UPI');
  const [orderType, setOrderType] = useState('Dine-in / Take Out');
  const [activeCategory, setActiveCategory] = useState('');
  const [popup, setPopup] = useState({ msg: '', type: 'danger', visible: false });
  const [isPrinting, setIsPrinting] = useState(false);

  // Modal states
  const [showCustomModal, setShowCustomModal] = useState(false);
  const [showAddMenuModal, setShowAddMenuModal] = useState(false);
  const [showAddCatModal, setShowAddCatModal] = useState(false);
  const [showDeleteCatModal, setShowDeleteCatModal] = useState(false);
  const [showDeleteMenuModal, setShowDeleteMenuModal] = useState(false);
  const [showEditMenuModal, setShowEditMenuModal] = useState(false);
  const [showPrintClearModal, setShowPrintClearModal] = useState(false);

  const popupTimer = useRef(null);

  const navigate = (hash) => { window.location.hash = hash; };

  const showPopup = useCallback((msg, type = 'danger') => {
    setPopup({ msg, type, visible: true });
    clearTimeout(popupTimer.current);
    popupTimer.current = setTimeout(() => setPopup(p => ({ ...p, visible: false })), 2200);
  }, []);

  // Load bill number from backend
  const loadBillNumber = useCallback(async () => {
    try {
      const res = await fetch(apiUrl('/api/token/current'));
      const data = await res.json();
      if (data.success) {
        setBillNumber(Number(data.token));
        localStorage.setItem('billNumber', data.token);
        localStorage.setItem('lastBillDate', new Date().toDateString());
      }
    } catch {
      const stored = localStorage.getItem('billNumber');
      setBillNumber(stored ? parseInt(stored) : 0);
    }
  }, []);

  // Unified, fully synchronized categories and menu builder
  const loadMenuAndCategories = useCallback(async (retryCount = 0) => {
    try {
      const [catsRes, itemsRes] = await Promise.all([
        fetch(apiUrl('/api/custom-categories'), { headers: getAuthHeadersOnly() }),
        fetch(apiUrl('/api/custom-items'), { headers: getAuthHeadersOnly() })
      ]);
      
      const catsData = await catsRes.json();
      const itemsData = await itemsRes.json();
      
      let cats = [];
      if (catsData.success && Array.isArray(catsData.categories)) {
        cats = catsData.categories.map(c => (c || '').trim()).filter(Boolean);
        setCustomCategories(cats.sort((a, b) => a.localeCompare(b)));
      }
      
      let items = [];
      if (itemsData.success && Array.isArray(itemsData.items)) {
        items = itemsData.items;
        setCustomItemIndex(items.map(i => ({
          name: i.name,
          price: i.price,
          category: i.category || 'Custom',
          imageUrl: i.imageUrl || ''
        })));
      }
      
      // Rebuild menuData completely from scratch (guarantees dynamic updates for add/edit/delete operations)
      const newMenuData = {};
      
      // Initialize active custom categories
      cats.forEach(c => {
        newMenuData[c] = [];
      });
      
      // Populate custom items into their respective category lists
      items.forEach(item => {
        const cat = item.category || 'Custom';
        if (!newMenuData[cat]) {
          newMenuData[cat] = [];
        }
        newMenuData[cat].push([item.name, item.price, item.imageUrl || '']);
      });
      
      setMenuData(newMenuData);

      // Keep activeCategory synchronized
      const categories = Object.keys(newMenuData);
      setActiveCategory(prev => {
        if (prev && newMenuData[prev]) {
          return prev;
        }
        return categories[0] || '';
      });
    } catch (err) {
      console.error("Error loading menu and categories:", err);
      if (retryCount < 4) {
        setTimeout(() => loadMenuAndCategories(retryCount + 1), 6000);
      }
    }
  }, []);

  // Restore draft
  useEffect(() => {
    try {
      const raw = localStorage.getItem(DRAFT_KEY);
      if (raw) {
        const saved = JSON.parse(raw);
        if (saved?.cart) setCart(saved.cart);
        if (saved?.payment) setPaymentMethod(saved.payment);
        if (saved?.orderType) setOrderType(saved.orderType);
      }
    } catch {}
  }, []);

  // Save draft on unmount or change
  const saveDraft = useCallback(() => {
    try {
      localStorage.setItem(DRAFT_KEY, JSON.stringify({ cart, payment: paymentMethod, orderType, updatedAt: Date.now() }));
    } catch {}
  }, [cart, paymentMethod, orderType]);

  useEffect(() => {
    window.addEventListener('beforeunload', saveDraft);
    return () => window.removeEventListener('beforeunload', saveDraft);
  }, [saveDraft]);

  // Escape key closes modals
  useEffect(() => {
    const handler = e => {
      if (e.key === 'Escape') {
        setShowCustomModal(false); setShowAddMenuModal(false);
        setShowAddCatModal(false); setShowDeleteCatModal(false);
        setShowDeleteMenuModal(false); setShowEditMenuModal(false);
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, []);

  useEffect(() => {
    loadBillNumber();
    loadMenuAndCategories();
  }, [loadBillNumber, loadMenuAndCategories]);

  // Cart operations
  const addToCart = useCallback((name, price) => {
    setCart(prev => {
      const updated = { ...prev };
      if (updated[name]) updated[name] = { ...updated[name], qty: updated[name].qty + 1 };
      else updated[name] = { price, qty: 1 };
      return updated;
    });
  }, []);

  const increaseQty = useCallback((name) => {
    setCart(prev => {
      if (!prev[name]) return prev;
      return { ...prev, [name]: { ...prev[name], qty: prev[name].qty + 1 } };
    });
  }, []);

  const decreaseQty = useCallback((name) => {
    setCart(prev => {
      if (!prev[name]) return prev;
      if (prev[name].qty <= 1) {
        const updated = { ...prev };
        delete updated[name];
        return updated;
      }
      return { ...prev, [name]: { ...prev[name], qty: prev[name].qty - 1 } };
    });
  }, []);

  const removeItem = useCallback((name) => {
    setCart(prev => { const u = { ...prev }; delete u[name]; return u; });
  }, []);

  const clearCart = useCallback(() => {
    setCart({});
    localStorage.removeItem(DRAFT_KEY);
    showPopup('Items Cleared', 'danger');
  }, [showPopup]);

  const total = Object.values(cart).reduce((sum, i) => sum + i.price * i.qty, 0);

  // Print receipt
  const printReceipt = useCallback(async () => {
    if (isPrinting) return;
    if (Object.keys(cart).length === 0 || total === 0) {
      alert('Please add items to the bill before printing.');
      return;
    }
    setIsPrinting(true);
    const billData = {
      items: Object.entries(cart).map(([name, item]) => ({ name, price: item.price, qty: item.qty })),
      total,
      payment: paymentMethod,
      orderType,
      token: billNumber
    };
    try {
      const res = await fetch(apiUrl('/api/bill'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(billData)
      });
      const data = await res.json();
      if (data.success) {
        if (data.token !== undefined) {
          setBillNumber(Number(data.token) + 1);
          localStorage.setItem('billNumber', Number(data.token) + 1);
        }
        window.print();
        setTimeout(() => {
          setIsPrinting(false);
          setShowPrintClearModal(true);
        }, 100);
      } else {
        alert('Error saving bill: ' + (data.error || 'Unknown error'));
        setIsPrinting(false);
      }
    } catch (err) {
      alert('Error saving bill: ' + err.message);
      setIsPrinting(false);
    }
  }, [isPrinting, cart, total, paymentMethod, orderType, billNumber]);

  const handlePrintClearOk = useCallback(() => {
    setShowPrintClearModal(false);
    setCart({});
    setPaymentMethod('UPI');
    setOrderType('Dine-in / Take Out');
    localStorage.removeItem(DRAFT_KEY);
    showPopup('Bill cleared for next order', 'gold');
  }, [showPopup]);

  const requireAdmin = useCallback((feature) => {
    if (!isAdmin()) { alert(`Access denied. Only admin can ${feature}.`); return false; }
    return true;
  }, []);

  const user = getCurrentUser();

  return (
    <div className="pos-shell">
      {/* ===== HEADER ===== */}
      <header className="header" role="banner">
        <div className="header-top-row">
          <div className="header-icons">
            <SettingsDropdown
              user={user}
              onAddCategory={() => { if (requireAdmin('manage menu categories')) setShowAddCatModal(true); }}
              onDeleteCategory={() => { if (requireAdmin('delete categories')) setShowDeleteCatModal(true); }}
              onAddMenu={() => { if (requireAdmin('add menu items')) setShowAddMenuModal(true); }}
              onEditMenu={() => { if (requireAdmin('edit menu items')) setShowEditMenuModal(true); }}
              onDeleteMenu={() => { if (requireAdmin('delete menu items')) setShowDeleteMenuModal(true); }}
              onLogout={logout}
            />
          </div>
          <div className="billing-portal-heading">
            <h1>Sri Vengamamba Food Court</h1>
            <h3>Billing Portal</h3>
            <p className="subtitle">Chinese Kitchen / Juice Bar</p>
          </div>
          <div className="analytics-btn-wrapper">
            <button className="header-icon-btn analytics-nav-btn" onClick={() => navigate('/analytics')} title="View Analytics">
              <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="btn-logo-svg">
                <line x1="18" y1="20" x2="18" y2="10"></line>
                <line x1="12" y1="20" x2="12" y2="4"></line>
                <line x1="6" y1="20" x2="6" y2="14"></line>
              </svg>
            </button>
          </div>
        </div>
        <div className="header-info">
          <div className="location"><strong>Location:</strong> Anits Campus Road, Sangivalasa,<br />Thagarapuvalasa, Vishakapatnam, AP - 531162</div>
          <div className="owner"><strong>Owner:</strong> Kesanapalli Sailaja</div>
        </div>
      </header>

      {/* ===== MAIN ===== */}
      <main className="container" role="main">
        <div className="left">
          <MenuPanel
            menuData={menuData}
            activeCategory={activeCategory}
            setActiveCategory={setActiveCategory}
            onAddItem={addToCart}
          />
        </div>

        <BillPanel
          cart={cart}
          total={total}
          billNumber={billNumber}
          paymentMethod={paymentMethod}
          orderType={orderType}
          onPaymentChange={setPaymentMethod}
          onOrderTypeChange={setOrderType}
          onIncrease={increaseQty}
          onDecrease={decreaseQty}
          onRemove={removeItem}
          onPrint={printReceipt}
          onClear={clearCart}
          isPrinting={isPrinting}
        />
      </main>

      {/* Floating Action Button: Add Custom Item */}
      <button 
        className="fab-add-custom-btn" 
        onClick={() => setShowCustomModal(true)} 
        title="Add Custom Item"
      >
        <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
          <line x1="12" y1="5" x2="12" y2="19"></line>
          <line x1="5" y1="12" x2="19" y2="12"></line>
        </svg>
      </button>

      <footer className="page-footer" role="contentinfo">
        <b>© ANITS 2023–2027 CSE 88 DEV</b>
      </footer>



      {/* ===== MODALS ===== */}
      {showCustomModal && (
        <CustomItemModal onClose={() => setShowCustomModal(false)} onAdd={addToCart} showPopup={showPopup} />
      )}
      {showAddMenuModal && (
        <AddMenuItemModal
          onClose={() => setShowAddMenuModal(false)}
          showPopup={showPopup}
          customCategories={customCategories}
          onRefresh={async (cat) => {
            await loadMenuAndCategories();
            if (cat) setActiveCategory(cat);
          }}
        />
      )}
      {showAddCatModal && (
        <AddCategoryModal
          onClose={() => setShowAddCatModal(false)}
          showPopup={showPopup}
          onAdded={async (name) => {
            await loadMenuAndCategories();
            setActiveCategory(name);
          }}
        />
      )}
      {showDeleteCatModal && (
        <DeleteCategoryModal
          onClose={() => setShowDeleteCatModal(false)}
          showPopup={showPopup}
          customCategories={customCategories}
          onRefresh={loadMenuAndCategories}
        />
      )}
      {showDeleteMenuModal && (
        <DeleteMenuModal
          onClose={() => setShowDeleteMenuModal(false)}
          showPopup={showPopup}
          customItemIndex={customItemIndex}
          onRefresh={loadMenuAndCategories}
        />
      )}
      {showEditMenuModal && (
        <EditMenuModal
          onClose={() => setShowEditMenuModal(false)}
          showPopup={showPopup}
          customItemIndex={customItemIndex}
          customCategories={customCategories}
          menuData={menuData}
          onRefresh={async (cat) => {
            await loadMenuAndCategories();
            if (cat) setActiveCategory(cat);
          }}
        />
      )}
      {showPrintClearModal && (
        <PrintClearModal onOk={handlePrintClearOk} />
      )}

      <StatusPopup msg={popup.msg} type={popup.type} visible={popup.visible} />
    </div>
  );
}

// ==========================================
// PAGE COMPONENT: ANALYTICS DASHBOARD
// ==========================================
function parseBillDate(bill) {
  const raw = bill.createdAtISO || bill.createdAt || bill.date || null;
  if (!raw) return null;
  if (typeof raw === 'string') {
    const hasTimezone = /[zZ]|[+-]\d{2}:?\d{2}$/.test(raw);
    const normalized = hasTimezone ? raw : `${raw}Z`;
    const parsed = new Date(normalized);
    return isNaN(parsed.getTime()) ? null : parsed;
  }
  const parsed = new Date(raw);
  return isNaN(parsed.getTime()) ? null : parsed;
}

function downloadAsXls(csvText, fileNameBase, sheetTitle) {
  if (typeof XLSX === 'undefined') {
    const bom = '\ufeff';
    const fallbackBlob = new Blob([bom + csvText], { type: 'text/csv;charset=utf-8;' });
    const fallbackLink = document.createElement('a');
    const fallbackUrl = URL.createObjectURL(fallbackBlob);
    fallbackLink.href = fallbackUrl;
    fallbackLink.download = `${fileNameBase}.csv`;
    fallbackLink.style.visibility = 'hidden';
    document.body.appendChild(fallbackLink);
    fallbackLink.click();
    setTimeout(() => {
      document.body.removeChild(fallbackLink);
      URL.revokeObjectURL(fallbackUrl);
    }, 200);
    return;
  }

  const rows = [];
  let currentRow = [];
  let currentCell = '';
  let inQuotes = false;

  for (let i = 0; i < csvText.length; i++) {
    const ch = csvText[i];
    const next = csvText[i + 1];

    if (ch === '"') {
      if (inQuotes && next === '"') {
        currentCell += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (ch === ',' && !inQuotes) {
      currentRow.push(currentCell);
      currentCell = '';
      continue;
    }

    if ((ch === '\n' || ch === '\r') && !inQuotes) {
      if (ch === '\r' && next === '\n') i++;
      currentRow.push(currentCell);
      if (currentRow.some(cell => String(cell).trim() !== '')) {
        rows.push(currentRow);
      }
      currentRow = [];
      currentCell = '';
      continue;
    }

    currentCell += ch;
  }

  if (currentCell.length || currentRow.length) {
    currentRow.push(currentCell);
    if (currentRow.some(cell => String(cell).trim() !== '')) {
      rows.push(currentRow);
    }
  }

  const worksheet = XLSX.utils.aoa_to_sheet(rows);

  if (rows.length > 0) {
    const colCount = rows.reduce((max, row) => Math.max(max, row.length), 0);
    worksheet['!cols'] = Array.from({ length: colCount }, (_, colIndex) => {
      let maxLen = 0;
      for (let r = 0; r < rows.length; r++) {
        const value = rows[r][colIndex] == null ? '' : String(rows[r][colIndex]);
        maxLen = Math.max(maxLen, value.length);
      }
      const width = Math.max(12, Math.min(48, maxLen + 2));
      return { wch: width };
    });
  }

  const workbook = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(workbook, worksheet, (sheetTitle || 'Report').slice(0, 31));

  const xlsxArray = XLSX.write(workbook, { bookType: 'xlsx', type: 'array' });
  const blob = new Blob([xlsxArray], {
    type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  });
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);

  link.href = url;
  link.download = `${fileNameBase}.xlsx`;
  link.style.visibility = 'hidden';

  document.body.appendChild(link);
  link.click();
  
  setTimeout(() => {
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }, 200);
}

function AnalyticsPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [dateMode, setDateMode] = useState('today');
  const [selectedDate, setSelectedDate] = useState('');
  const [rangeFrom, setRangeFrom] = useState('');
  const [rangeTo, setRangeTo] = useState('');
  const [allBills, setAllBills] = useState([]);
  const [filtered, setFiltered] = useState([]);
  const [billSearch, setBillSearch] = useState('');
  const [stats, setStats] = useState({ total: 0, count: 0, avg: 0, peak: '--:--', weekTotal: 0, weekCount: 0, monthTotal: 0, monthCount: 0 });
  const [payBreakdown, setPayBreakdown] = useState({});
  const [billsPage, setBillsPage] = useState(1);
  const BILLS_PER_PAGE = 50;

  const [popup, setPopup] = useState({ msg: '', type: 'danger', visible: false });
  const popupTimer = useRef(null);

  const showPopup = useCallback((msg, type = 'danger') => {
    setPopup({ msg, type, visible: true });
    clearTimeout(popupTimer.current);
    popupTimer.current = setTimeout(() => setPopup(p => ({ ...p, visible: false })), 2200);
  }, []);

  // New States for Multi-Delete & Report Download options
  const [selectedBillsForDelete, setSelectedBillsForDelete] = useState(new Set());
  const [showManageModal, setShowManageModal] = useState(false);
  const [showConfirmDeleteModal, setShowConfirmDeleteModal] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [showDownloadModal, setShowDownloadModal] = useState(false);

  const todayVal = useMemo(() => {
    const d = new Date();
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const date = String(d.getDate()).padStart(2, '0');
    return `${year}-${month}-${date}`;
  }, []);

  const [downloadFromDate, setDownloadFromDate] = useState(todayVal);
  const [downloadToDate, setDownloadToDate] = useState(todayVal);

  const itemsChartRef = useRef(null);
  const payChartRef = useRef(null);
  const salesChartRef = useRef(null);
  const chartInstances = useRef({});

  const navigate = (hash) => { window.location.hash = hash; };

  const loadAnalytics = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await fetch(apiUrl('/api/bills?includeDeleted=true'));
      if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
      const text = await res.text();
      if (!text) { setLoading(false); return; }
      const bills = JSON.parse(text);
      if (!bills || !Array.isArray(bills)) { setLoading(false); return; }
      setAllBills(bills);
    } catch (err) {
      setError('Error loading data: ' + err.message);
    }
    setLoading(false);
  }, []);

  useEffect(() => { loadAnalytics(); }, [loadAnalytics]);

  // Filter bills whenever mode or data changes
  useEffect(() => {
    const activeBills = allBills.filter(b => !b.deleted);
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const weekStart = new Date(today); weekStart.setDate(today.getDate() - today.getDay());
    const monthStart = new Date(today); monthStart.setDate(1);

    let f = activeBills;
    if (dateMode === 'today') {
      f = activeBills.filter(b => { const d = parseBillDate(b); if (!d) return false; d.setHours(0,0,0,0); return d.getTime() === today.getTime(); });
    } else if (dateMode === 'week') {
      f = activeBills.filter(b => { const d = parseBillDate(b); if (!d) return false; d.setHours(0,0,0,0); return d.getTime() >= weekStart.getTime(); });
    } else if (dateMode === 'month') {
      f = activeBills.filter(b => { const d = parseBillDate(b); if (!d) return false; d.setHours(0,0,0,0); return d.getTime() >= monthStart.getTime(); });
    } else if (dateMode === 'custom' && selectedDate) {
      const customDate = new Date(selectedDate); customDate.setHours(0,0,0,0);
      f = activeBills.filter(b => { const d = parseBillDate(b); if (!d) return false; d.setHours(0,0,0,0); return d.getTime() === customDate.getTime(); });
    } else if (dateMode === 'range' && rangeFrom && rangeTo) {
      const rf = new Date(rangeFrom), rt = new Date(rangeTo);
      f = activeBills.filter(b => { const d = parseBillDate(b); if (!d) return false; return d >= rf && d <= rt; });
    }

    setFiltered(f);
    setBillsPage(1);

    // Stats
    const totalSales = f.reduce((s, b) => s + (b.total || 0), 0);
    const count = f.length;
    const avg = count > 0 ? Math.round(totalSales / count) : 0;
    // Peak hour
    const hourCounts = {};
    f.forEach(b => { const d = parseBillDate(b); if (d) { const h = d.getHours(); hourCounts[h] = (hourCounts[h] || 0) + 1; } });
    const peakHour = Object.entries(hourCounts).reduce((a, b) => a[1] > b[1] ? a : b, [0, 0])[0];
    // Week / month totals
    const weekBills = activeBills.filter(b => { const d = parseBillDate(b); if (!d) return false; d.setHours(0,0,0,0); return d.getTime() >= weekStart.getTime(); });
    const monthBills = activeBills.filter(b => { const d = parseBillDate(b); if (!d) return false; d.setHours(0,0,0,0); return d.getTime() >= monthStart.getTime(); });
    setStats({
      total: totalSales, count, avg,
      peak: Object.keys(hourCounts).length > 0 ? String(peakHour).padStart(2,'0') + ':00' : '--:--',
      weekTotal: weekBills.reduce((s, b) => s + (b.total || 0), 0), weekCount: weekBills.length,
      monthTotal: monthBills.reduce((s, b) => s + (b.total || 0), 0), monthCount: monthBills.length
    });
    // Payment breakdown
    const pay = {};
    f.forEach(b => { const m = b.payment || 'Unknown'; pay[m] = (pay[m] || 0) + (b.total || 0); });
    setPayBreakdown(pay);
  }, [allBills, dateMode, selectedDate, rangeFrom, rangeTo]);

  // Checklist period filtering (includes soft-deleted bills)
  const rangeBills = useMemo(() => {
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const weekStart = new Date(today); weekStart.setDate(today.getDate() - today.getDay());
    const monthStart = new Date(today); monthStart.setDate(1);

    return allBills.filter(b => {
      const d = parseBillDate(b);
      if (!d) return false;
      d.setHours(0, 0, 0, 0);

      if (dateMode === 'today') {
        return d.getTime() === today.getTime();
      } else if (dateMode === 'week') {
        return d.getTime() >= weekStart.getTime();
      } else if (dateMode === 'month') {
        return d.getTime() >= monthStart.getTime();
      } else if (dateMode === 'custom' && selectedDate) {
        const customDate = new Date(selectedDate); customDate.setHours(0, 0, 0, 0);
        return d.getTime() === customDate.getTime();
      } else if (dateMode === 'range' && rangeFrom && rangeTo) {
        const rf = new Date(rangeFrom), rt = new Date(rangeTo);
        const billD = parseBillDate(b);
        return billD >= rf && billD <= rt;
      }
      return true;
    });
  }, [allBills, dateMode, selectedDate, rangeFrom, rangeTo]);

  // Excel Range Export
  const downloadAnalyticsWithRange = useCallback((fromDate, toDate) => {
    try {
      if (!fromDate || !toDate) {
        showPopup('Please select both From Date and To Date', 'danger');
        return;
      }

      const from = new Date(fromDate + 'T00:00:00');
      const to = new Date(toDate + 'T23:59:59');

      if (from > to) {
        showPopup('From Date must be before To Date', 'danger');
        return;
      }

      const filteredBills = allBills.filter(bill => {
        if (bill.deleted) return false;
        const billDate = parseBillDate(bill);
        if (!billDate) return false;
        return billDate >= from && billDate <= to;
      });

      if (filteredBills.length === 0) {
        showPopup('No bills found in the selected date range', 'danger');
        return;
      }

      const billsByDay = {};
      filteredBills.forEach(bill => {
        const billDate = parseBillDate(bill);
        if (!billDate) return;
        const dateStr = billDate.toISOString().slice(0, 10);
        if (!billsByDay[dateStr]) {
          billsByDay[dateStr] = [];
        }
        billsByDay[dateStr].push(bill);
      });

      let csvContent = 'SVFC Chinese Kitchen - Daily Sales Report (Custom Date Range)\n';
      csvContent += `Report Date: ${new Date().toLocaleString('en-IN')}\n`;
      csvContent += `Period: ${fromDate} to ${toDate}\n\n`;
      csvContent += 'SI.NO,Date,Bills Generated,Total Amount (₹),Cash,UPI,Average Bill (₹)\n';

      let siNo = 1;
      let grandTotal = 0;
      let grandCash = 0;
      let grandUPI = 0;
      let totalBillsCount = 0;

      const sortedDates = Object.keys(billsByDay).sort();

      sortedDates.forEach(date => {
        const dayBills = billsByDay[date];

        let dayTotal = 0;
        let cash = 0;
        let upi = 0;

        dayBills.forEach(bill => {
          dayTotal += bill.total || 0;
          const payment = bill.payment || 'Unknown';
          if (payment === 'Cash' || payment === 'Cash / UPI' || payment === 'Cash/UPI') {
            cash += bill.total || 0;
          } else if (payment === 'UPI') {
            upi += bill.total || 0;
          }
        });

        const avgBill = dayBills.length > 0 ? Math.round(dayTotal / dayBills.length) : 0;

        csvContent += `${siNo},${date},${dayBills.length},${dayTotal},${cash},${upi},${avgBill}\n`;

        grandTotal += dayTotal;
        grandCash += cash;
        grandUPI += upi;
        totalBillsCount += dayBills.length;
        siNo++;
      });

      const grandAvg = totalBillsCount > 0 ? Math.round(grandTotal / totalBillsCount) : 0;
      csvContent += `TOTAL,,${totalBillsCount},${grandTotal},${grandCash},${grandUPI},${grandAvg}\n\n`;

      csvContent += 'PAYMENT METHOD BREAKDOWN\n';
      csvContent += 'Payment Method,Amount (₹),Count\n';

      const paymentBreakdown = {};
      filteredBills.forEach(bill => {
        let method = bill.payment || 'Unknown';
        if (method === 'Cash / UPI' || method === 'Cash' || method === 'Cash/UPI') {
          method = 'Cash';
        } else if (method === 'UPI') {
          method = 'UPI';
        }

        if (!paymentBreakdown[method]) {
          paymentBreakdown[method] = { amount: 0, count: 0 };
        }
        paymentBreakdown[method].amount += bill.total || 0;
        paymentBreakdown[method].count++;
      });

      Object.entries(paymentBreakdown).forEach(([method, data]) => {
        csvContent += `${method},${data.amount},${data.count}\n`;
      });
      csvContent += `\nGRAND TOTAL,${grandTotal}\n`;

      const fileName = `svfc-chinese-kitchen-report_${fromDate}_to_${toDate}`;
      downloadAsXls(csvContent, fileName, 'SVFC Sales Report');
      showPopup('Report downloaded successfully', 'success');
    } catch (error) {
      showPopup('Error downloading report: ' + error.message, 'danger');
    }
  }, [allBills, showPopup]);

  // Single Bill Deletion Action
  const triggerSingleDelete = (bill) => {
    const key = `${bill.token}_${bill.createdAtISO || bill.createdAt}`;
    setSelectedBillsForDelete(new Set([key]));
    setShowConfirmDeleteModal(true);
  };

  // Multi-delete modal launch
  const handlePermanentDeleteSubmit = () => {
    if (selectedBillsForDelete.size === 0) return;
    setShowManageModal(false);
    setShowConfirmDeleteModal(true);
  };

  // Parallelized API permanent deletion
  const confirmPermanentDelete = async () => {
    setDeleting(true);
    setShowConfirmDeleteModal(false);

    const selectedBills = rangeBills.filter(b => {
      const key = `${b.token}_${b.createdAtISO || b.createdAt}`;
      return selectedBillsForDelete.has(key);
    });

    const token = localStorage.getItem('authToken') || localStorage.getItem('token');
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    };

    let deletedCount = 0;
    let failedCount = 0;

    try {
      await Promise.all(selectedBills.map(async (b) => {
        try {
          const createdAtVal = b.createdAtISO || b.createdAt || '';
          const deleteUrl = apiUrl(`/api/bill/${b.token}/permanent-delete?createdAtISO=${encodeURIComponent(createdAtVal)}`);
          const response = await fetch(deleteUrl, {
            method: 'DELETE',
            headers,
            body: JSON.stringify({ createdAtISO: createdAtVal || null })
          });

          if (response.ok) {
            deletedCount++;
          } else {
            failedCount++;
          }
        } catch (err) {
          failedCount++;
        }
      }));

      // In-memory local state filter for dynamic updates
      setAllBills(prev => prev.filter(b => {
        const key = `${b.token}_${b.createdAtISO || b.createdAt}`;
        return !selectedBillsForDelete.has(key);
      }));

      setSelectedBillsForDelete(new Set());

      if (deletedCount > 0) {
        if (failedCount > 0) {
          showPopup(`Deleted ${deletedCount} bills, ${failedCount} failed`, 'danger');
        } else {
          showPopup(`Permanently deleted ${deletedCount} bill${deletedCount > 1 ? 's' : ''}!`, 'danger');
        }
      } else {
        showPopup('Failed to permanently delete selected bills.', 'danger');
      }
    } catch (err) {
      showPopup('Error during permanent deletion: ' + err.message, 'danger');
    } finally {
      setDeleting(false);
    }
  };

  // Item aggregates
  const itemAggs = useMemo(() => {
    const counts = {}, totals = {};
    filtered.forEach(b => { (b.items || []).forEach(i => { counts[i.name] = (counts[i.name] || 0) + (i.qty || 1); totals[i.name] = (totals[i.name] || 0) + (i.price || 0) * (i.qty || 1); }); });
    return Object.entries(counts).map(([name, qty]) => ({ name, qty, total: totals[name] || 0 })).sort((a,b) => b.total - a.total);
  }, [filtered]);

  // Bill table rows
  const billRows = useMemo(() => {
    return filtered.map((bill, idx) => {
      const d = parseBillDate(bill);
      return {
        token: bill.token || bill.billNo || (idx + 1),
        date: d ? d.toLocaleString('en-IN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: true }) : '--',
        orderType: bill.orderType || 'Dine-in / Take Out',
        items: (bill.items || []).length,
        total: bill.total || 0,
        payment: bill.payment || 'Unknown'
      };
    });
  }, [filtered]);

  const searchedBills = useMemo(() => {
    const q = billSearch.toLowerCase().trim();
    if (!q) return billRows;
    return billRows.filter(b => String(b.token).includes(q) || b.payment.toLowerCase().includes(q) || b.orderType.toLowerCase().includes(q));
  }, [billRows, billSearch]);

  const totalPages = Math.ceil(searchedBills.length / BILLS_PER_PAGE) || 1;
  const pagedBills = searchedBills.slice((billsPage - 1) * BILLS_PER_PAGE, billsPage * BILLS_PER_PAGE);

  // Charts
  useEffect(() => {
    if (loading || !window.Chart) return;
    const drawCharts = () => {
      const topItems = itemAggs.slice(0, 10);
      if (itemsChartRef.current && topItems.length > 0) {
        if (chartInstances.current.items) chartInstances.current.items.destroy();
        chartInstances.current.items = new window.Chart(itemsChartRef.current, {
          type: 'bar',
          data: { labels: topItems.map(i => i.name), datasets: [{ label: 'Orders', data: topItems.map(i => i.qty), backgroundColor: 'rgba(255,213,79,0.7)', borderColor: 'rgba(255,179,0,1)', borderWidth: 2 }] },
          options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { ticks: { color: 'rgba(255,255,255,0.6)' }, grid: { color: 'rgba(255,213,79,0.1)' } }, x: { ticks: { color: 'rgba(255,255,255,0.6)' }, grid: { color: 'rgba(255,213,79,0.1)' } } } }
        });
      }
      const payKeys = Object.keys(payBreakdown);
      if (payChartRef.current && payKeys.length > 0) {
        if (chartInstances.current.pay) chartInstances.current.pay.destroy();
        chartInstances.current.pay = new window.Chart(payChartRef.current, {
          type: 'doughnut',
          data: { labels: payKeys, datasets: [{ data: payKeys.map(k => payBreakdown[k]), backgroundColor: ['rgba(251,191,36,0.85)','rgba(74,222,128,0.85)','rgba(245,158,11,0.85)','rgba(248,113,113,0.85)','rgba(251,146,60,0.85)'], borderWidth: 2 }] },
          options: { responsive: true, maintainAspectRatio: false }
        });
      }
      if (salesChartRef.current) {
        const activeBills = allBills.filter(b => !b.deleted);
        const today2 = new Date(); today2.setHours(0,0,0,0);
        const last7 = [], sales7 = [];
        for (let i = 6; i >= 0; i--) {
          const d = new Date(today2); d.setDate(d.getDate() - i);
          const dayBills = activeBills.filter(b => { const bd = parseBillDate(b); if (!bd) return false; bd.setHours(0,0,0,0); return bd.getTime() === d.getTime(); });
          last7.push(d.toLocaleDateString('en-IN', { month: 'short', day: 'numeric' }));
          sales7.push(dayBills.reduce((s, b) => s + (b.total || 0), 0));
        }
        if (chartInstances.current.sales) chartInstances.current.sales.destroy();
        chartInstances.current.sales = new window.Chart(salesChartRef.current, {
          type: 'line',
          data: { labels: last7, datasets: [{ label: 'Sales (₹)', data: sales7, borderColor: 'rgba(255,213,79,1)', backgroundColor: 'rgba(255,213,79,0.1)', borderWidth: 2, fill: true, tension: 0.4, pointBackgroundColor: 'rgba(255,213,79,1)', pointBorderColor: '#fff', pointBorderWidth: 2, pointRadius: 5 }] },
          options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: 'rgba(255,255,255,0.8)' } } }, scales: { y: { ticks: { color: 'rgba(255,255,255,0.6)' }, grid: { color: 'rgba(255,213,79,0.1)' } }, x: { ticks: { color: 'rgba(255,255,255,0.6)' }, grid: { color: 'rgba(255,213,79,0.1)' } } } }
        });
      }
    };
    drawCharts();
  }, [loading, itemAggs, payBreakdown, allBills]);

  return (
    <div className="analytics-shell">
      <header className="analytics-header">
        <h1>Sri Vengamamba Food Court</h1>
        <h3>Analytics Dashboard</h3>
        <p className="subtitle">Sales & Revenue Analytics</p>
        <div className="header-nav-buttons">
          <button className="download-report-nav-btn" onClick={() => setShowDownloadModal(true)} title="Download Report">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="btn-logo-svg">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="7 10 12 15 17 10"></polyline>
              <line x1="12" y1="15" x2="12" y2="3"></line>
            </svg>
          </button>
          <button className="back-btn" onClick={() => navigate('/')}>
            ← Back to POS
          </button>
        </div>
      </header>

      <div className="analytics-container">
        <div className="analytics-content">
          {loading && <div className="loading">Loading analytics data...</div>}
          {error && <div className="error-message">{error}</div>}
          {!loading && !error && (
            <>
              {/* Date Picker */}
              <div className="date-picker-panel">
                <div className="date-controls">
                  {['today','week','month','custom','range'].map(mode => (
                    <button key={mode} className={`date-btn ${dateMode === mode ? 'active' : ''}`} onClick={() => setDateMode(mode)}>
                      {mode === 'today' ? 'Today' : mode === 'week' ? 'This Week' : mode === 'month' ? 'This Month' : mode === 'custom' ? 'Pick Date' : 'Date Range'}
                    </button>
                  ))}
                </div>
                {dateMode === 'custom' && (
                  <div className="range-controls">
                    <div className="calendar-picker-wrapper">
                      <span className="calendar-label">Date</span>
                      <CustomDatePicker className="custom-date-input" value={selectedDate} onChange={setSelectedDate} />
                    </div>
                  </div>
                )}
                {dateMode === 'range' && (
                  <div className="range-controls">
                    <div className="calendar-picker-wrapper">
                      <span className="calendar-label">From</span>
                      <CustomDatePicker className="custom-date-input" value={rangeFrom} onChange={setRangeFrom} />
                    </div>
                    <div className="calendar-picker-wrapper">
                      <span className="calendar-label">To</span>
                      <CustomDatePicker className="custom-date-input" value={rangeTo} onChange={setRangeTo} />
                    </div>
                  </div>
                )}
              </div>

              {/* Stats Grid */}
              <div className="stats-grid" style={{ marginTop: '16px' }}>
                <div className="stat-card stat-revenue"><div className="stat-label">Revenue</div><div className="stat-value">₹{stats.total.toLocaleString('en-IN')}</div></div>
                <div className="stat-card stat-count"><div className="stat-label">Bills</div><div className="stat-value">{stats.count}</div></div>
                <div className="stat-card stat-avg"><div className="stat-label">Avg Bill</div><div className="stat-value">₹{stats.avg.toLocaleString('en-IN')}</div></div>
                <div className="stat-card"><div className="stat-label">Peak Hour</div><div className="stat-value" style={{ fontSize: '28px' }}>{stats.peak}</div></div>
                <div className="stat-card"><div className="stat-label">Week Revenue</div><div className="stat-value" style={{ color: '#4dd0a0', fontSize: '28px' }}>₹{stats.weekTotal.toLocaleString('en-IN')}</div></div>
                <div className="stat-card"><div className="stat-label">Month Revenue</div><div className="stat-value" style={{ color: '#ffb74d', fontSize: '28px' }}>₹{stats.monthTotal.toLocaleString('en-IN')}</div></div>
              </div>

              {/* Charts */}
              <div className="charts-grid">
                <div className="chart-container">
                  <div className="chart-title">Top Items by Orders</div>
                  <div className="chart-canvas">
                    {itemAggs.length === 0 ? (
                      <div className="chart-placeholder">No sales data available</div>
                    ) : (
                      <canvas ref={itemsChartRef} />
                    )}
                  </div>
                </div>
                <div className="chart-container">
                  <div className="chart-title">Payment Methods</div>
                  <div className="chart-canvas">
                    {Object.keys(payBreakdown).length === 0 ? (
                      <div className="chart-placeholder">No payment data available</div>
                    ) : (
                      <canvas ref={payChartRef} />
                    )}
                  </div>
                </div>
                <div className="chart-container">
                  <div className="chart-title">Sales Trend (Last 7 Days)</div>
                  <div className="chart-canvas"><canvas ref={salesChartRef} /></div>
                </div>
                <div className="payment-breakdown">
                  <h3>Payment Breakdown</h3>
                  {Object.entries(payBreakdown).map(([method, amount]) => (
                    <div key={method} className="payment-item">
                      <span className="payment-method">{method}</span>
                      <span className="payment-amount">₹{amount.toLocaleString('en-IN')}</span>
                    </div>
                  ))}
                  {Object.keys(payBreakdown).length === 0 && <div className="no-data">No data</div>}
                </div>
              </div>

              {/* Items Report */}
              <div className="report-section">
                <h3>Items Report</h3>
                <table className="report-table">
                  <thead><tr><th>Item</th><th>Qty</th><th>Amount</th></tr></thead>
                  <tbody>
                    {itemAggs.length === 0 ? (
                      <tr><td colSpan="3" className="no-data">No data available</td></tr>
                    ) : (
                      <>
                        {itemAggs.map(i => (
                          <tr key={i.name}>
                            <td>{i.name}</td>
                            <td className="qty-cell">{i.qty}</td>
                            <td className="amount-cell">₹{i.total.toLocaleString('en-IN')}</td>
                          </tr>
                        ))}
                        <tr className="report-total">
                          <td><strong>TOTAL</strong></td>
                          <td className="qty-cell"><strong>{itemAggs.reduce((s,i)=>s+i.qty,0)}</strong></td>
                          <td className="amount-cell"><strong>₹{itemAggs.reduce((s,i)=>s+i.total,0).toLocaleString('en-IN')}</strong></td>
                        </tr>
                      </>
                    )}
                  </tbody>
                </table>
              </div>

              {/* Bills Register */}
              <div className="report-section">
                <h3>
                  <span>Complete Bill Register <span style={{ fontSize: '14px', fontWeight: 400, color: '#999' }}>(Page {billsPage} of {totalPages})</span></span>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    {isAdmin() && (
                      <button className="manage-bills-inline-btn" onClick={() => setShowManageModal(true)}>
                        Manage Bills
                      </button>
                    )}
                    <button className="toggle-hidden-btn" onClick={() => setBillsPage(p => Math.max(1, p-1))} disabled={billsPage === 1} style={{ minWidth: '40px' }}>◀</button>
                    <button className="toggle-hidden-btn" onClick={() => setBillsPage(p => Math.min(totalPages, p+1))} disabled={billsPage >= totalPages} style={{ minWidth: '40px' }}>▶</button>
                  </div>
                </h3>
                <div className="search-panel">
                  <input type="text" className="search-input" value={billSearch} onChange={e => { setBillSearch(e.target.value); setBillsPage(1); }} placeholder="Search by Bill No, Payment Method, or Order Type..." />
                </div>
                <table className="report-table">
                  <thead>
                    <tr>
                      <th>Bill No</th><th>Date &amp; Time</th><th>Order Type</th><th>Items</th><th>Amount</th><th>Payment</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pagedBills.length === 0 ? (
                      <tr><td colSpan="6" className="no-data">No data available</td></tr>
                    ) : (
                      pagedBills.map((b, idx) => (
                        <tr key={`${b.token}-${idx}`}>
                          <td className="bill-no-cell">{b.token}</td>
                          <td>{b.date}</td>
                          <td className="event-cell">{b.orderType}</td>
                          <td className="qty-cell">{b.items}</td>
                          <td className="amount-cell">₹{b.total.toLocaleString('en-IN')}</td>
                          <td>{b.payment}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Admin checklist multi-delete modal */}
      {showManageModal && (
        <div className="modal-overlay" onClick={e => e.target === e.currentTarget && setShowManageModal(false)}>
          <div className="modal-content" style={{ maxWidth: '420px', background: 'linear-gradient(135deg, rgba(10,10,10,0.95) 0%, rgba(20,20,20,0.95) 100%)', border: '2px solid var(--gold-dark)' }}>
            <div className="modal-header">
              <h2 style={{ color: 'var(--gold)', margin: 0 }}>Delete Bills</h2>
              <button className="modal-close" onClick={() => setShowManageModal(false)} style={{ color: '#aaa' }}>×</button>
            </div>
            <p style={{ margin: '0 0 14px 0', fontSize: '13px', color: '#999' }}>Select one or more bills to permanently delete:</p>

            <div className="delete-toolbar">
              <button className="delete-toolbar-btn select-all" onClick={() => setSelectedBillsForDelete(new Set(rangeBills.map(b => `${b.token}_${b.createdAtISO || b.createdAt}`)))}>Select All</button>
              <button className="delete-toolbar-btn clear-all" onClick={() => setSelectedBillsForDelete(new Set())}>Clear</button>
              <span className="delete-selected-count">{selectedBillsForDelete.size} selected</span>
            </div>

            <div className="bill-checklist-wrap">
              {rangeBills.length === 0 ? (
                <div style={{ padding: '16px', color: '#666', textAlign: 'center', fontSize: '13px' }}>No bills found for the selected period.</div>
              ) : (
                rangeBills.map(b => {
                  const key = `${b.token}_${b.createdAtISO || b.createdAt}`;
                  const isChecked = selectedBillsForDelete.has(key);
                  const d = parseBillDate(b);
                  const formattedDate = d ? d.toLocaleString('en-IN', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: true }) : '--';
                  return (
                    <div key={key} className={`bill-checklist-item ${b.deleted ? 'hidden-bill' : ''}`} onClick={() => {
                      setSelectedBillsForDelete(prev => {
                        const next = new Set(prev);
                        next.has(key) ? next.delete(key) : next.add(key);
                        return next;
                      });
                    }}>
                      <input type="checkbox" checked={isChecked} onChange={() => {}} />
                      <label style={{ cursor: 'pointer' }}>
                        <strong>Bill #{b.token || b.billNo}</strong> - ₹{b.total} ({b.payment})<br />
                        <span style={{ fontSize: '11px', color: '#888' }}>{formattedDate} {b.deleted ? '[Soft-Deleted]' : ''}</span>
                      </label>
                    </div>
                  );
                })
              )}
            </div>

            {selectedBillsForDelete.size > 0 && (
              <p style={{ margin: '10px 0 0 0', padding: '10px 12px', background: 'rgba(211,47,47,0.2)', borderLeft: '3px solid #ff6b6b', color: '#ff9999', fontSize: '12px', borderRadius: '3px' }}>
                ⛔ WARNING: Selected bills will be permanently deleted. This CANNOT be undone!
              </p>
            )}

            <div className="delete-modal-actions" style={{ marginTop: '14px', display: 'flex', gap: '10px' }}>
              <button className="delete-cancel-btn" onClick={() => setShowManageModal(false)} style={{ flex: 1, padding: '10px 16px', background: 'rgba(255,255,255,0.1)', border: '1px solid rgba(255,255,255,0.2)', color: '#ccc', borderRadius: '4px', fontWeight: '600', cursor: 'pointer', fontSize: '13px' }}>
                Cancel
              </button>
              <button className="permanent-delete-btn" disabled={selectedBillsForDelete.size === 0} onClick={handlePermanentDeleteSubmit} style={{ flex: 1, padding: '10px 16px', borderRadius: '4px', fontWeight: '700', cursor: selectedBillsForDelete.size === 0 ? 'not-allowed' : 'pointer', fontSize: '13px' }}>
                Delete Selected
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirmation multi-delete/single-delete permanent modal */}
      {showConfirmDeleteModal && (
        <div className="modal-overlay" onClick={e => e.target === e.currentTarget && setShowConfirmDeleteModal(false)}>
          <div className="modal-content" style={{ maxWidth: '400px', background: '#ffffff', borderRadius: '12px', padding: '24px', textAlign: 'center' }}>
            <h3 style={{ color: '#000', margin: '0 0 12px 0', fontSize: '20px' }}>⚠️ Confirm Permanent Delete</h3>
            <p style={{ color: '#555', margin: '0 0 20px 0', fontSize: '14px' }}>
              You are about to permanently delete <strong>{selectedBillsForDelete.size} bill(s)</strong>. This <strong>cannot be undone</strong>.
            </p>
            <div style={{ background: 'rgba(211, 47, 47, 0.1)', borderLeft: '3px solid #d32f2f', padding: '10px', margin: '10px 0', borderRadius: '4px', fontSize: '12px', color: '#d32f2f', textAlign: 'left' }}>
              All selected bills will be completely removed from the database.
            </div>
            <div className="delete-modal-actions" style={{ display: 'flex', gap: '10px', marginTop: '20px' }}>
              <button className="delete-cancel-btn" onClick={() => {
                setShowConfirmDeleteModal(false);
                setSelectedBillsForDelete(new Set());
              }} style={{ flex: 1, padding: '12px', border: 'none', borderRadius: '8px', fontWeight: '600', cursor: 'pointer', background: '#e0e0e0', color: '#333' }}>
                Cancel
              </button>
              <button className="permanent-delete-btn" onClick={confirmPermanentDelete} style={{ flex: 1, padding: '12px', border: 'none', borderRadius: '8px', fontWeight: '700', cursor: 'pointer', color: '#fff' }}>
                Yes, Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Excel Report Download Modal */}
      {showDownloadModal && (
        <div className="modal-overlay" onClick={e => e.target === e.currentTarget && setShowDownloadModal(false)}>
          <div className="modal-content download-modal-content">
            <div className="modal-header">
              <h2 style={{ color: 'var(--green)', margin: 0 }}>Download Analytics Report</h2>
              <button className="modal-close" onClick={() => setShowDownloadModal(false)}>×</button>
            </div>
            <div className="download-modal-fields">
              <div className="download-report-field">
                <label>From Date</label>
                <CustomDatePicker value={downloadFromDate} onChange={setDownloadFromDate} className="custom-date-input download-modal-date-input" />
              </div>
              <div className="download-report-field">
                <label>To Date</label>
                <CustomDatePicker value={downloadToDate} onChange={setDownloadToDate} className="custom-date-input download-modal-date-input" />
              </div>
              <button className="download-report-btn" onClick={() => { downloadAnalyticsWithRange(downloadFromDate, downloadToDate); setShowDownloadModal(false); }}>
                Download Report
              </button>
            </div>
          </div>
        </div>
      )}

      <footer className="analytics-footer">
        <b>© ANITS 2023–2027 CSE 88 DEV</b>
      </footer>

      <StatusPopup msg={popup.msg} type={popup.type} visible={popup.visible} />
    </div>
  );
}

// ==========================================
// CORE APP ROUTER & INITIALIZER
// ==========================================
function App() {
  const [currentHash, setCurrentHash] = useState(window.location.hash || '#/');
  const [user, setUser] = useState(getCurrentUser());

  useEffect(() => {
    const handleHashChange = () => {
      setCurrentHash(window.location.hash || '#/');
    };
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  const handleLoginSuccess = () => {
    setUser(getCurrentUser());
  };

  // Basic Routing Rules
  const token = localStorage.getItem('authToken');

  // 1. If not authenticated, always show LoginPage
  if (!token) {
    return <LoginPage onLoginSuccess={handleLoginSuccess} />;
  }

  // 2. Route mappings based on Hash
  if (currentHash === '#/login') {
    return <LoginPage onLoginSuccess={handleLoginSuccess} />;
  } else if (currentHash === '#/analytics') {
    return <AnalyticsPage />;
  } else {
    return <POSPage />;
  }
}

// Bootstrap React
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);

