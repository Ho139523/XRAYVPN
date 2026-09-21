(function () {
  'use strict';
  var data = JSON.parse(document.getElementById('data').textContent);
  var tr = data.i18n;
  var $ = function (id) { return document.getElementById(id); };

  // ---- copy buttons (clipboard API needs HTTPS, so fall back to execCommand)
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) { return navigator.clipboard.writeText(text); }
    var area = document.createElement('textarea');
    area.value = text; area.style.position = 'fixed'; area.style.opacity = '0';
    document.body.appendChild(area); area.select();
    try { document.execCommand('copy'); } catch (e) { /* ignore */ }
    document.body.removeChild(area);
    return Promise.resolve();
  }
  Array.prototype.forEach.call(document.querySelectorAll('[data-copy]'), function (button) {
    button.addEventListener('click', function () {
      copyText(button.getAttribute('data-copy')).then(function () {
        button.textContent = tr.copied;
        setTimeout(function () { button.textContent = tr.copy; }, 1500);
      });
    });
  });

  // ---- sites: show the place picker only for the two place-based modes
  var siteForm = $('site-form');
  var zonePick = $('zonepick');
  function syncMode() {
    var mode = siteForm.querySelector('input[name=mode]:checked').value;
    zonePick.hidden = mode === 'always';
  }
  Array.prototype.forEach.call(siteForm.querySelectorAll('input[name=mode]'), function (radio) {
    radio.addEventListener('change', syncMode);
  });
  syncMode();

  Array.prototype.forEach.call(document.querySelectorAll('[data-edit]'), function (button) {
    button.addEventListener('click', function () {
      var site = JSON.parse(button.getAttribute('data-edit'));
      $('site-input').value = site.site;
      siteForm.querySelector('input[name=mode][value=' + site.mode + ']').checked = true;
      Array.prototype.forEach.call(siteForm.querySelectorAll('input[name=zones]'), function (box) {
        box.checked = site.zones.indexOf(box.value) !== -1;
      });
      syncMode();
      siteForm.scrollIntoView({ behavior: 'smooth', block: 'center' });
      $('site-input').focus();
    });
  });

  // ---- places on a map
  var mapEl = $('map');
  if (!mapEl || !window.L) { return; }
  var L = window.L;
  L.Icon.Default.prototype.options.imagePath = '/admin/static/leaflet/images/';

  var map = L.map(mapEl).setView(data.center, 12);
  L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 19, attribution: '&copy; OpenStreetMap contributors'
  }).addTo(map);

  var fields = {
    id: $('zone-id'), name: $('zone-name'), lat: $('zone-lat'), lon: $('zone-lon'),
    radius: $('zone-radius'), range: $('zone-range'), networks: $('zone-networks'), coords: $('zone-coords')
  };
  var draft = { marker: null, circle: null };
  var shapes = L.featureGroup().addTo(map);

  function radius() { return Math.max(20, parseInt(fields.radius.value, 10) || 150); }

  function showCoords() {
    fields.coords.textContent = fields.lat.value ?
      tr.coords + ': ' + Number(fields.lat.value).toFixed(5) + ', ' + Number(fields.lon.value).toFixed(5) : '';
  }

  function setDraft(lat, lon) {
    fields.lat.value = lat; fields.lon.value = lon;
    if (!draft.marker) {
      draft.marker = L.marker([lat, lon], { draggable: true }).addTo(map);
      draft.marker.on('dragend', function () {
        var p = draft.marker.getLatLng(); setDraft(p.lat, p.lng);
      });
      draft.circle = L.circle([lat, lon], { radius: radius(), color: '#2563eb', weight: 2, fillOpacity: .15 }).addTo(map);
    } else {
      draft.marker.setLatLng([lat, lon]);
      draft.circle.setLatLng([lat, lon]);
    }
    draft.circle.setRadius(radius());
    showCoords();
  }

  function clearDraft() {
    if (draft.marker) { map.removeLayer(draft.marker); map.removeLayer(draft.circle); }
    draft.marker = draft.circle = null;
    fields.lat.value = fields.lon.value = '';
    showCoords();
  }

  function setRadius(value) {
    fields.radius.value = value;
    fields.range.value = Math.min(2000, Math.max(50, value));
    if (draft.circle) { draft.circle.setRadius(radius()); }
  }

  fields.range.addEventListener('input', function () { setRadius(parseInt(fields.range.value, 10)); });
  fields.radius.addEventListener('input', function () { setRadius(radius()); });
  map.on('click', function (event) { setDraft(event.latlng.lat, event.latlng.lng); });

  function loadPlace(zone) {
    fields.id.value = zone.id; fields.name.value = zone.name;
    fields.networks.value = (zone.networks || []).join('\n');
    if (zone.networks && zone.networks.length) { fields.networks.closest('details').open = true; }
    setRadius(zone.radius || 150);
    if (zone.lat !== null) {
      setDraft(zone.lat, zone.lon);
      map.fitBounds(draft.circle.getBounds(), { maxZoom: 17 });
    } else { clearDraft(); }
    $('zone-form').scrollIntoView({ behavior: 'smooth', block: 'center' });
    fields.name.focus();
  }

  function resetForm() {
    fields.id.value = ''; fields.name.value = ''; fields.networks.value = '';
    setRadius(150); clearDraft();
  }
  $('zone-new').addEventListener('click', resetForm);

  data.zones.forEach(function (zone) {
    if (zone.lat === null) { return; }
    var circle = L.circle([zone.lat, zone.lon], {
      radius: zone.radius, color: '#059669', weight: 2, dashArray: '6 4', fillOpacity: .12
    }).bindTooltip(zone.name, { permanent: true, direction: 'center', className: 'zone-label' });
    circle.on('click', function (event) { L.DomEvent.stopPropagation(event); loadPlace(zone); });
    shapes.addLayer(circle);
  });
  if (shapes.getLayers().length) { map.fitBounds(shapes.getBounds().pad(.3), { maxZoom: 16 }); }

  Array.prototype.forEach.call(document.querySelectorAll('[data-zone]'), function (button) {
    button.addEventListener('click', function () { loadPlace(JSON.parse(button.getAttribute('data-zone'))); });
  });

  $('zone-form').addEventListener('submit', function (event) {
    if (!fields.lat.value && !fields.networks.value.trim()) {
      event.preventDefault(); alert(tr.map_pick_first);
    }
  });

  // ---- address search (OpenStreetMap Nominatim)
  function search() {
    var query = $('q').value.trim();
    var message = $('search-msg');
    if (!query) { return; }
    message.textContent = '…';
    fetch('https://nominatim.openstreetmap.org/search?format=jsonv2&limit=1&accept-language=' +
          encodeURIComponent(data.lang) + '&q=' + encodeURIComponent(query))
      .then(function (response) { return response.json(); })
      .then(function (results) {
        if (!results.length) { message.textContent = tr.search_none; return; }
        message.textContent = results[0].display_name;
        var lat = parseFloat(results[0].lat), lon = parseFloat(results[0].lon);
        map.setView([lat, lon], 16);
        setDraft(lat, lon);
      })
      .catch(function () { message.textContent = tr.search_none; });
  }
  $('search').addEventListener('click', search);
  $('q').addEventListener('keydown', function (event) {
    if (event.key === 'Enter') { event.preventDefault(); search(); }
  });
})();
