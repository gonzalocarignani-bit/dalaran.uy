// ── DALARAN CART ─────────────────────────────────────────────
// Shared cart state via localStorage. Used by index, product, cart pages.

var DalaranCart = (function() {
  var KEY = 'dalaran_cart_v1';

  function load() {
    try { return JSON.parse(localStorage.getItem(KEY)) || []; }
    catch(e) { return []; }
  }

  function save(items) {
    try { localStorage.setItem(KEY, JSON.stringify(items)); }
    catch(e) {}
    _notify();
  }

  // Add item or increment qty
  function add(product) {
    // product: { id, name, image, priceText, priceValue }
    var items = load();
    var existing = items.find(function(i){ return i.id === product.id; });
    if (existing) {
      existing.qty = (existing.qty || 1) + 1;
    } else {
      items.push({ id: product.id, name: product.name, image: product.image || '',
                   priceText: product.priceText, priceValue: product.priceValue, qty: 1 });
    }
    save(items);
  }

  function remove(productId) {
    save(load().filter(function(i){ return i.id !== productId; }));
  }

  function setQty(productId, qty) {
    var items = load();
    var item = items.find(function(i){ return i.id === productId; });
    if (!item) return;
    if (qty <= 0) { remove(productId); return; }
    item.qty = qty;
    save(items);
  }

  function clear() { save([]); }

  function count() {
    return load().reduce(function(s, i){ return s + (i.qty||1); }, 0);
  }

  function total() {
    return load().reduce(function(s, i){ return s + (i.priceValue||0) * (i.qty||1); }, 0);
  }

  // Observer pattern so all pages react to changes
  var _listeners = [];
  function onChange(fn) { _listeners.push(fn); }
  function _notify() { _listeners.forEach(function(fn){ try{fn();}catch(e){} }); }

  return { load, save, add, remove, setQty, clear, count, total, onChange };
})();
