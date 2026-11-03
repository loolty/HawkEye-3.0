/* Adds a per-table sort selector and direction button to staff data tables. */
(() => {
  const tables = [...document.querySelectorAll('.content table')];
  const norm = v => (v || '').trim().replace(/\s+/g,' ');
  const val = (row, i) => norm(row.cells[i]?.innerText);
  const compare = (a,b) => {
    const da=Date.parse(a), db=Date.parse(b);
    if (!Number.isNaN(da) && !Number.isNaN(db)) return da-db;
    const na=Number(a.replace(/[^0-9.-]/g,'')), nb=Number(b.replace(/[^0-9.-]/g,''));
    if (a && b && Number.isFinite(na) && Number.isFinite(nb) && /[0-9]/.test(a) && /[0-9]/.test(b)) return na-nb;
    return a.localeCompare(b, undefined, {numeric:true,sensitivity:'base'});
  };
  tables.forEach((table, ti) => {
    const head=table.tHead?.rows[0]; const body=table.tBodies[0];
    if (!head || !body || head.cells.length<2) return;
    const wrap=table.closest('.card') || table.parentElement;
    const bar=document.createElement('div'); bar.className='table-sortbar actions';
    const label=document.createElement('label'); label.textContent='Sort by'; label.style.margin='0'; label.style.alignSelf='center';
    const select=document.createElement('select'); select.setAttribute('aria-label','Choose table sort column');
    [...head.cells].forEach((th,i)=>{ const t=norm(th.innerText); if (!t || /action|quick/i.test(t)) return; const o=document.createElement('option'); o.value=i; o.textContent=t; select.appendChild(o); });
    if (!select.options.length) return;
    const direction=document.createElement('button'); direction.type='button'; direction.className='btn btn-small'; direction.textContent='Ascending ↑'; let asc=true;
    const sort=()=>{const idx=Number(select.value); const rows=[...body.rows]; rows.sort((ra,rb)=>compare(val(ra,idx),val(rb,idx))*(asc?1:-1)); rows.forEach(r=>body.appendChild(r));};
    select.addEventListener('change',sort); direction.addEventListener('click',()=>{asc=!asc; direction.textContent=asc?'Ascending ↑':'Descending ↓'; sort();});
    bar.append(label,select,direction); table.parentNode.insertBefore(bar,table);   // parentNode: the table may sit inside a wrapper div
  });
})();
