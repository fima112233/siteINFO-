(() => {
  const esc = s => (s||'').replace(/[&<>]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));

  async function api(path, opts={}){
    const r = await fetch(path, {headers:{'Content-Type':'application/json'}, ...opts});
    const d = await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(d.error || r.status);
    return d;
  }

  function fmtDate(s){
    if(!s) return '—';
    try{ return s.slice(0,19).replace('T',' '); }catch(e){ return s; }
  }

  // ---- статистика ----
  async function loadStats(){
    const s = await api('/api/admin/stats');
    document.getElementById('sUsers').textContent = s.users;
    document.getElementById('sAdmins').textContent = s.admins;
    document.getElementById('sActive').textContent = s.active_users;
    document.getElementById('sConversations').textContent = s.conversations;
    document.getElementById('sMessages').textContent = s.messages;
    document.getElementById('sScans').textContent = s.scans;
    document.getElementById('sReports').textContent = s.reports;
    document.getElementById('sRunning').textContent = s.running_jobs;
  }

  // ---- пользователи ----
  async function loadUsers(){
    const users = await api('/api/admin/users');
    const body = document.getElementById('usersBody');
    if(!users.length){ body.innerHTML='<tr><td colspan="9" class="loading">нет пользователей</td></tr>'; return; }
    body.innerHTML = users.map(u=>`
      <tr data-uid="${u.id}">
        <td>${u.id}</td>
        <td>${esc(u.username)}</td>
        <td><span class="badge ${u.is_admin?'admin':'user'}">${u.is_admin?'админ':'юзер'}</span></td>
        <td><span class="badge ${u.is_active?'on':'off'}">${u.is_active?'активен':'заблокирован'}</span></td>
        <td>${u.conv_count}</td>
        <td>${u.scan_count}</td>
        <td>${fmtDate(u.created_at)}</td>
        <td>${fmtDate(u.last_login)}</td>
        <td>
          <button class="mini-btn" data-act="toggle-admin">${u.is_admin?'снять админа':'дать админа'}</button>
          <button class="mini-btn" data-act="toggle-active">${u.is_active?'заблокировать':'разблокировать'}</button>
          <button class="mini-btn danger" data-act="delete">удалить</button>
        </td>
      </tr>`).join('');
  }

  // ---- чаты ----
  async function loadConvs(){
    const convs = await api('/api/admin/conversations');
    const body = document.getElementById('convsBody');
    if(!convs.length){ body.innerHTML='<tr><td colspan="6" class="loading">нет чатов</td></tr>'; return; }
    body.innerHTML = convs.map(c=>`
      <tr data-cid="${c.id}">
        <td>${c.id}</td>
        <td>${esc(c.username)}</td>
        <td>${c.msg_count}</td>
        <td>${c.scan_count}</td>
        <td>${fmtDate(c.created_at)}</td>
        <td><button class="mini-btn" data-act="view">открыть</button>
            <button class="mini-btn danger" data-act="delete">удалить</button></td>
      </tr>`).join('');
  }

  // ---- просмотр чата ----
  async function viewConv(cid){
    const d = await api(`/api/admin/conversations/${cid}`);
    const viewer = document.getElementById('viewerContent');
    let msgs = [];
    const kinds = { user:'[user]', stage:'[этап]', ok:'[ok]', err:'[err]', block:'[block]', final:'[результат]', note:'[note]' };
    for(const m of d.messages){
      const cls = {final:'final', user:'user'}[m.kind] || '';
      msgs.push(`<div><span class="kind ${cls}">${kinds[m.kind]||m.kind}</span> ${esc(String(m.content).slice(0, 4000))}</div>`);
      if(m.content && m.content.length > 4000) msgs.push('<div class="kind">… (обрезано)</div>');
      msgs.push('<br>');
    }
    viewer.innerHTML = msgs.length
      ? msgs.join('')
      : '<div class="loading">В чате нет сообщений</div>';
  }

  // ---- действия ----
  async function onBodyClick(e, kind){
    const btn = e.target.closest('.mini-btn');
    if(!btn) return;
    const act = btn.dataset.act;
    const row = btn.closest('tr');
    if(kind==='users'){
      const uid = row.dataset.uid;
      try{
        if(act==='toggle-admin'){ await api(`/api/admin/users/${uid}`,{method:'PATCH',body:JSON.stringify({is_admin: btn.textContent.includes('снять')?0:1})}); }
        else if(act==='toggle-active'){ await api(`/api/admin/users/${uid}`,{method:'PATCH',body:JSON.stringify({is_active: btn.textContent.includes('заблокировать')?0:1})}); }
        else if(act==='delete'){ if(confirm('Удалить пользователя и все его чаты?')) await api(`/api/admin/users/${uid}`,{method:'DELETE'}); }
        loadUsers(); loadStats();
      }catch(err){ alert('Ошибка: '+err.message); }
    } else if(kind==='convs'){
      const cid = row.dataset.cid;
      if(act==='view'){
        // открыть реальный чат-интерфейс с историей этого чата (от имени админа)
        window.location.href = `/?view=${cid}`;
      }
      else if(act==='delete'){ if(confirm('Удалить чат?')){ await api(`/api/admin/conversations/${cid}`,{method:'DELETE'}); loadConvs(); loadStats(); } }
    }
  }

  document.getElementById('usersBody').addEventListener('click', e=>onBodyClick(e,'users'));
  document.getElementById('convsBody').addEventListener('click', e=>onBodyClick(e,'convs'));

  // ---- табы ----
  function showTab(name){
    document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('active', t.dataset.tab===name));
    document.getElementById('panel-users').classList.toggle('hidden', name!=='users');
    document.getElementById('panel-convs').classList.toggle('hidden', name!=='convs');
    document.getElementById('panel-viewer').classList.toggle('hidden', name!=='viewer');
  }
  document.querySelectorAll('.tab').forEach(t=>t.addEventListener('click', ()=>showTab(t.dataset.tab)));
  document.getElementById('closeViewer').addEventListener('click', ()=>showTab('convs'));

  document.getElementById('logoutBtn').addEventListener('click', async ()=>{
    await fetch('/api/logout',{method:'POST'}); window.location.href='/auth';
  });

  // ---- init ----
  loadStats();
  loadUsers();
  loadConvs();
  setInterval(()=>{ loadStats(); }, 5000);   // живое обновление статистики
})();