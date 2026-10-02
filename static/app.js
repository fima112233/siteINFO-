(() => {
  const chat = document.getElementById('chat');
  const log = document.getElementById('log');
  const input = document.getElementById('urlInput');
  const goBtn = document.getElementById('goBtn');
  const newChatBtn = document.getElementById('newChatBtn');
  const logoutBtn = document.getElementById('logoutBtn');
  const convList = document.getElementById('convList');
  const scanStatus = document.getElementById('scanStatus');

  // ---- состояние ----
  let currentConvId = window.CURRENT_CID || null;
  let okCount = 0, errCount = 0;
  let thinking = null;          // текущий свёрнутый блок «Думаю…»

  const ICONS = { stage:'⬛', ok:'✅', err:'⚠️', block:'🔶', final:'🟢' };

  function esc(s){ return (s||'').replace(/[&<>]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
  function stamp(){ try{ return new Date().toLocaleTimeString('ru-RU',{hour12:false}); }catch(e){ return ''; } }
  function scrollBottom(){ chat.scrollTop = chat.scrollHeight; }

  // ---- блок «Думаю…» (свёрнутый, со стрелкой) ----
  function createThinking(){
    const el = document.createElement('div');
    el.className = 'msg thinking';

    const icon = document.createElement('div');
    icon.className='ico'; icon.textContent='🧠';

    const body = document.createElement('div');
    body.className='body';

    const ttl = document.createElement('div');
    ttl.className='ttl';
    const chev = document.createElement('span');
    chev.className='chev'; chev.textContent='▸';
    const name = document.createElement('span');
    name.className='name'; name.textContent='Думаю…';
    const counter = document.createElement('span');
    counter.className='counter'; counter.textContent='0';
    const cursor = document.createElement('span');
    cursor.className='cursor'; cursor.textContent='▌';
    const ts = document.createElement('span');
    ts.className='stamp'; ts.textContent=stamp();
    ttl.append(chev, name, counter, cursor, ts);
    body.appendChild(ttl);

    const detail = document.createElement('div');
    detail.className='detail';
    detail.style.display='none';   // свёрнут

    chev.onclick=()=>{
      const open = detail.style.display !== 'none';
      if (open){ detail.style.display='none'; chev.textContent='▸'; }
      else { detail.style.display='block'; chev.textContent='▾'; scrollBottom(); }
    };
    body.appendChild(detail);

    el.append(icon, body);
    log.appendChild(el);
    return { el, name, counter, cursor, detail, chev, icon };
  }

  function appendThinkingLine(iconChar, text){
    if (!thinking) return;
    const line = document.createElement('div');
    line.className='tline';
    line.innerHTML=`<span class="t-ico">${iconChar}</span><span class="t-txt">${esc(text)}</span>`;
    thinking.detail.appendChild(line);
    if (thinking.detail.style.display !== 'none'){
      thinking.detail.scrollTop = thinking.detail.scrollHeight;
    }
  }

  function updateCounter(){
    if (!thinking) return;
    thinking.counter.textContent = `${okCount}✓ / ${errCount}✗`;
  }

  function finishThinking(){
    if (!thinking) return;
    thinking.name.textContent='Готово';
    thinking.icon.textContent='✅';
    thinking.cursor.remove();
    thinking.counter.textContent=`итог: ${okCount}✓ / ${errCount}✗`;
    // остаётся свёрнутым
  }

  // ---- рендер сообщения ----
  function addMsg(msg){
    const kind = msg.kind;

    // СИНЕЕ сообщение юзера (баблсправа) — в диалоге
    if (kind === 'user'){
      const el = document.createElement('div');
      el.className='msg user';
      const bubble = document.createElement('div');
      bubble.className='user-bubble';
      bubble.textContent = msg.content;
      const ts = document.createElement('div');
      ts.className='bubble-stamp'; ts.textContent=stamp();
      el.appendChild(bubble);
      el.appendChild(ts);
      log.appendChild(el); scrollBottom(); return el;
    }

    const el = document.createElement('div');
    el.className = `msg ${kind}`;

    const icon = document.createElement('div');
    icon.className='ico'; icon.textContent = ICONS[kind]||'•';

    const body = document.createElement('div');
    body.className='body';

    const ttl = document.createElement('div');
    ttl.className='ttl';
    const name = document.createElement('span');
    name.className='name';
    const ts = document.createElement('span');
    ts.className='stamp'; ts.textContent = stamp();

    if (kind === 'stage'){
      name.textContent = msg.content || 'этап';
    } else if (kind === 'ok'){
      name.textContent = msg.name || 'OK';
    } else if (kind === 'err'){
      name.textContent = (msg.name||'ошибка') + ' — ' + (msg.msg||'');
    } else if (kind === 'block'){
      name.textContent = msg.name || '';
    } else if (kind === 'final'){
      name.textContent = 'Итоговый отчёт';
    } else if (kind === 'note'){
      name.textContent = msg.content || '';
    }
    ttl.appendChild(name);
    if (kind !== 'stage') ttl.appendChild(ts);
    body.appendChild(ttl);

    // контент
    if (kind === 'ok' && msg.detail){
      const d=document.createElement('div'); d.className='detail'; d.textContent=msg.detail;
      const chev=document.createElement('span'); chev.className='chev'; chev.textContent='▾';
      chev.title='показать/скрыть';
      name.parentElement.insertBefore(chev, ts);
      chev.onclick=()=>{ const o=d.classList.toggle('open'); chev.textContent=o?'▴':'▾'; if(o)scrollBottom(); };
      body.appendChild(d);
    } else if (kind === 'final' && msg.content){
      const r=document.createElement('div'); r.className='report'; r.textContent=msg.content;
      const wrap=document.createElement('div'); wrap.className='detail open'; wrap.appendChild(r);
      body.appendChild(wrap);
    } else if (kind === 'block' && msg.detail){
      const d=document.createElement('div'); d.className='detail open'; d.textContent=msg.detail;
      body.appendChild(d);
    }

    el.append(icon, body);
    log.appendChild(el);
    scrollBottom();
    return el;
  }

  // ---- асинхронная привязка SSE к текущему чату ----
  // один чат может гнать несколько прогонов одновременно (хоть сто штук),
  // каждый — свои SSE-поток и кандидат в список активных.
  const activeStreams = new Map();   // jobId -> {es, convId, url}

  function attachStream(convId, jobId, url){
    if (activeStreams.has(jobId)) return;
    const es = new EventSource(`/api/stream/${jobId}`);
    activeStreams.set(jobId, {es, convId, url});

    // все этапы прогона уходят в один свёрнутый блок «Думаю…»
    es.addEventListener('stage', e=>{ ensureConvVisible(convId); if(!thinking) thinking=createThinking(); const p=JSON.parse(e.data); appendThinkingLine('·', p.text); });
    es.addEventListener('ok', e=>{ ensureConvVisible(convId); if(!thinking) thinking=createThinking(); okCount++; const p=JSON.parse(e.data); appendThinkingLine('✅', p.name||''); updateCounter(); });
    es.addEventListener('err', e=>{ ensureConvVisible(convId); if(!thinking) thinking=createThinking(); errCount++; const p=JSON.parse(e.data); appendThinkingLine('⚠️', (p.name||'') + (p.msg? ' — '+p.msg : '')); updateCounter(); });
    es.addEventListener('block', e=>{ ensureConvVisible(convId); if(!thinking) thinking=createThinking(); const p=JSON.parse(e.data); appendThinkingLine('🔶', (p.name||'') + (p.detail? ' — '+p.detail : '')); });
    es.addEventListener('final', e=>{ ensureConvVisible(convId); finishThinking(); const p=JSON.parse(e.data); addMsg({kind:'final', content:p.text}); });
    es.addEventListener('terminal', e=>{ ensureConvVisible(convId); if(!thinking) thinking=createThinking(); appendThinkingLine('💥', p.text); });
    es.addEventListener('done', e=>{
      const s = activeStreams.get(jobId);
      if (s){ es.close(); activeStreams.delete(jobId); }
      updateScanIndicator();
      refreshSidebar();
    });
    es.onerror = ()=>{ const s = activeStreams.get(jobId); if(s) activeStreams.delete(jobId); es.close(); updateScanIndicator(); };
  }

  // показываем чат, в который прилетел результат, если он выбран
  function ensureConvVisible(convId){
    if (currentConvId !== convId){
      currentConvId = convId;
      document.querySelectorAll('.conv').forEach(el=>el.classList.toggle('active', +el.dataset.cid===convId));
    }
  }

  // ---- кнопка Пробить <-> Стоп ----
  let scanning = false;
  function updateGoButton(){
    const any = activeStreams.size > 0;
    scanning = any;
    goBtn.textContent = any ? 'Стоп' : 'Пробить';
    goBtn.classList.toggle('stop', any);
    scanStatus.style.display = any ? '' : 'none';
    scanStatus.textContent = any ? `идёт пробив: ${activeStreams.size} …` : '';
  }

  function stopAll(){
    for (const [jobId, s] of activeStreams.entries()){
      fetch(`/api/scan/${jobId}/cancel`, {method:'POST'}).catch(()=>{});
    }
    updateGoButton();
  }

  function updateScanIndicator(){ updateGoButton(); }

  async function scan(){
    const url = input.value.trim();
    if (!url) return;

    // если идёт прогон — кнопка работает как Стоп
    if (activeStreams.size > 0){ stopAll(); return; }

    // сбрасываем блок «Думаю» и счётчики перед новым прогоном
    okCount = 0; errCount = 0;

    // если ещё нет чата — создаём
    let cid = currentConvId;
    try{
      if (!cid){
        const r = await (await fetch('/api/conversation/new',{method:'POST'})).json();
        cid = r.conv_id;
        currentConvId = cid;
        await openConversation(cid, true);
      }
      addMsg({kind:'user', content:url});
      thinking = createThinking();   // синий юзер + свёрнутый «Думаю»

      const resp = await fetch('/api/scan',{
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({url, conv_id: cid})
      });
      const data = await resp.json();
      if(!resp.ok) throw new Error(data.error||'ошибка');
      attachStream(cid, data.job_id, url);
      updateGoButton();
      input.value='';
    }catch(err){
      addMsg({kind:'note', content:'Ошибка запуска: '+err.message});
    }
  }

  // ---- история / переключение чатов ----
  async function openConversation(cid, isNew){
    currentConvId = cid;
    // сброс состояния прогона/блоков при переключении
    okCount = 0; errCount = 0; thinking = null;
    // подсветка
    document.querySelectorAll('.conv').forEach(el=>el.classList.toggle('active', +el.dataset.cid===cid));
    log.innerHTML='';
    if (isNew){ return; }
    const msgs = await (await fetch(`/api/conversation/${cid}/messages`)).json();
    for (const m of msgs) addMsg(m);
  }

  function refreshSidebar(){
    // перезагрузить список чатов
    fetch('/').then(r=>r.text()).then(html=>{
      const tmp=document.createElement('div'); tmp.innerHTML=html;
      const newList=tmp.querySelector('#convList');
      if(newList) convList.innerHTML=newList.innerHTML;
      bindConvClicks();
    }).catch(()=>{});
  }

  function bindConvClicks(){
    document.querySelectorAll('.conv').forEach(el=>{
      el.onclick=()=>{ openConversation(+el.dataset.cid, false); };
    });
  }

  async function newChat(){
    const r = await (await fetch('/api/conversation/new',{method:'POST'})).json();
    currentConvId = r.conv_id;
    refreshSidebar();
    openConversation(r.conv_id, true);
    input.focus();
  }

  // ---- init ----
  function init(){
    updateGoButton();
    bindConvClicks();
    // если пришли с админки с параметром ?view=<cid> — сразу открыть этот чат
    if (currentConvId){
      openConversation(currentConvId, false);
    }
    goBtn.addEventListener('click', scan);
    input.addEventListener('keydown', e=>{ if(e.key==='Enter') scan(); });
    newChatBtn.addEventListener('click', newChat);
    logoutBtn.addEventListener('click', async ()=>{
      await fetch('/api/logout',{method:'POST'}); window.location.href='/auth';
    });
  }
  init();
})();