// Tabs
document.querySelectorAll('[data-tab]').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = btn.dataset.tab;
    const container = btn.closest('[data-tabs]') || document;
    container.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    container.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    const content = document.getElementById('tab-' + target);
    if (content) content.classList.add('active');
  });
});

// Cerrar dialogs al click fuera
document.querySelectorAll('dialog').forEach(d => {
  d.addEventListener('click', e => { if (e.target === d) d.close(); });
});

// Auto-submit selects de filtro
document.querySelectorAll('[data-autosubmit]').forEach(el => {
  el.addEventListener('change', () => el.closest('form').submit());
});

// Confirmaciones
document.querySelectorAll('[data-confirm]').forEach(el => {
  el.addEventListener('click', e => {
    if (!confirm(el.dataset.confirm)) e.preventDefault();
  });
});

// Deshabilitar botón al enviar
document.querySelectorAll('[data-loading]').forEach(btn => {
  btn.closest('form')?.addEventListener('submit', () => {
    btn.disabled = true;
    btn.textContent = btn.dataset.loading;
  });
});

// Hacer modales arrastrable y mejor manejo
document.querySelectorAll('dialog').forEach(d => {
  const h2 = d.querySelector('h2');
  if (h2 && !h2.closest('.modal-header')) {
    // Envolver el h2 en un header si no lo tiene
    const header = document.createElement('div');
    header.className = 'modal-header';
    h2.parentNode.insertBefore(header, h2);
    header.appendChild(h2);
    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'modal-close';
    closeBtn.innerHTML = '✕';
    closeBtn.onclick = () => d.close();
    header.appendChild(closeBtn);

    // Envolver el contenido restante en modal-body
    const body = document.createElement('div');
    body.className = 'modal-body';
    while (d.children.length > 1) body.appendChild(d.children[1]);
    d.appendChild(body);
  }

  // Drag por el header
  const header = d.querySelector('.modal-header');
  if (header) {
    let isDragging = false, startX, startY, offsetX = 0, offsetY = 0;
    header.addEventListener('mousedown', e => {
      if (e.target.closest('.modal-close')) return;
      isDragging = true;
      startX = e.clientX - offsetX;
      startY = e.clientY - offsetY;
      d.style.transition = 'none';
    });
    document.addEventListener('mousemove', e => {
      if (!isDragging) return;
      offsetX = e.clientX - startX;
      offsetY = e.clientY - startY;
      d.style.transform = `translate(calc(-50% + ${offsetX}px), calc(-50% + ${offsetY}px))`;
    });
    document.addEventListener('mouseup', () => { isDragging = false; });
  }
});

// Toggle pantalla completa de PDF
function togglePdfFull(btn){
  const wrap = btn.closest('.pdf-wrapper');
  wrap.classList.toggle('fullscreen');
  btn.textContent = wrap.classList.contains('fullscreen') ? '✕' : '⛶';
  btn.title = wrap.classList.contains('fullscreen') ? 'Salir de pantalla completa' : 'Pantalla completa';
}
window.togglePdfFull = togglePdfFull;

// ESC para salir de fullscreen
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.pdf-wrapper.fullscreen').forEach(w => {
      w.classList.remove('fullscreen');
      const btn = w.querySelector('.pdf-toolbar-btn[onclick*="togglePdfFull"]');
      if (btn) { btn.textContent = '⛶'; btn.title = 'Pantalla completa'; }
    });
  }
});
