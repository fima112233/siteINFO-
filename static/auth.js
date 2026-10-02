(() => {
  const form = document.getElementById('authForm');
  const username = document.getElementById('username');
  const password = document.getElementById('password');
  const errEl = document.getElementById('authErr');
  const btn = document.getElementById('authBtn');
  const switchLink = document.getElementById('switchLink');
  const authSwitch = document.getElementById('authSwitch');

  let mode = 'login';

  function setMode(m){
    mode = m;
    btn.textContent = m === 'login' ? 'Войти' : 'Создать аккаунт';
    switchLink.textContent = m === 'login' ? 'Зарегистрироваться' : 'Войти';
    password.autocomplete = m === 'login' ? 'current-password' : 'new-password';
    errEl.textContent = '';
  }

  switchLink.addEventListener('click', ()=> setMode(mode==='login'?'register':'login'));
  authSwitch.addEventListener('click', (e)=>{ if(e.target===authSwitch) return; });

  form.addEventListener('submit', async (e)=>{
    e.preventDefault();
    errEl.textContent = '';
    btn.disabled = true; btn.textContent = '...';
    try{
      const resp = await fetch('/api/'+mode, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({username: username.value.trim(), password: password.value})
      });
      const data = await resp.json();
      if(!resp.ok){ throw new Error(data.error || 'ошибка'); }
      window.location.href = '/';
    }catch(err){
      errEl.textContent = err.message;
      btn.disabled = false; btn.textContent = mode==='login'?'Войти':'Создать аккаунт';
    }
  });
})();