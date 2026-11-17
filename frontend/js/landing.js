/* landing.js - behaviour for the landing page that lives inside index.html
   Sign In / Get Started hides the landing page and shows the login screen (already in index.html).
   If the user already has a saved session, the landing page is skipped automatically. */
var landing = document.getElementById("landingPage");
var AUTH_TOKEN_KEY_LANDING = "vulenser_access_token";   /* same key used by auth.js */

function isHidden(){ return landing.classList.contains("ld-hidden"); }
function hideLanding(){ landing.classList.add("ld-hidden"); window.scrollTo(0,0); }
function showLanding(){ landing.scrollTop = 0; landing.classList.remove("ld-hidden"); }

/* already signed in -> go straight to the app */
try { if (sessionStorage.getItem(AUTH_TOKEN_KEY_LANDING)) hideLanding(); } catch (e) {}

/* Sign In / Get Started buttons */
landing.querySelectorAll("a.go").forEach(function(a){
  a.addEventListener("click", function(e){ e.preventDefault(); hideLanding(); });
});

/* "Back to home" button on the login screen -> shows the landing page again */
(function(){
  var shell = document.getElementById("authShell");
  if (!shell) return;
  var b = document.createElement("button");
  b.type = "button";
  b.className = "ld-home-btn";
  b.textContent = "\u2190 Back to home";
  b.addEventListener("click", showLanding);
  shell.appendChild(b);
})();

/* "See how" and logo links scroll inside the landing container */
landing.querySelectorAll('a[href^="#ld"]').forEach(function(a){
  a.addEventListener("click", function(e){
    e.preventDefault();
    var t = document.getElementById(a.getAttribute("href").slice(1));
    if (t) t.scrollIntoView({behavior:"smooth", block:"start"});
  });
});

var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/* typed words */
(function(){
  var w=["Requirements","User Stories","Specs","Login Flows"], el=document.getElementById("ldTyped"), i=0,j=0,del=false;
  if(reduce){el.textContent=w[0];return;}
  (function tick(){
    if(isHidden()){setTimeout(tick,500);return;}
    var t=w[i];
    el.textContent=t.slice(0,j);
    if(!del&&j<t.length){j++;setTimeout(tick,90);}
    else if(!del){del=true;setTimeout(tick,1500);}
    else if(j>0){j--;setTimeout(tick,45);}
    else{del=false;i=(i+1)%w.length;setTimeout(tick,300);}
  })();
})();

/* scroll reveal + counters */
(function(){
  var els=document.querySelectorAll(".rv");
  function count(c){
    var to=+c.dataset.to,s=null;
    (function f(t){s=s||t;var p=Math.min((t-s)/1200,1);c.textContent=Math.round(to*(1-Math.pow(1-p,3)));if(p<1)requestAnimationFrame(f);})(performance.now());
  }
  var io=new IntersectionObserver(function(es){es.forEach(function(e){
    if(e.isIntersecting){e.target.classList.add("in");var c=e.target.querySelector(".cnt");if(c)count(c);io.unobserve(e.target);}
  });},{threshold:.15});
  els.forEach(function(e,i){e.style.transitionDelay=(i%3)*110+"ms";io.observe(e);});
})();

/* scroll progress (landing page scrolls inside its own container) */
landing.addEventListener("scroll",function(){
  document.getElementById("ldBar").style.transform="scaleX("+(landing.scrollTop/(landing.scrollHeight-landing.clientHeight||1))+")";
},{passive:true});

/* cursor glow, 3D tilt, card spotlight */
(function(){
  if(reduce)return;
  var hero=document.getElementById("ldHero"),cg=document.getElementById("ldCg"),tl=document.getElementById("ldTilt");
  hero.addEventListener("mousemove",function(e){
    var r=hero.getBoundingClientRect();
    cg.style.left=(e.clientX-r.left)+"px";cg.style.top=(e.clientY-r.top)+"px";
    var x=(e.clientX/innerWidth-.5),y=(e.clientY/innerHeight-.5);
    tl.style.transform="rotateY("+(x*14)+"deg) rotateX("+(-y*10)+"deg)";
  });
  hero.addEventListener("mouseleave",function(){tl.style.transform="";});
  document.querySelectorAll(".card").forEach(function(c){
    c.addEventListener("mousemove",function(e){
      var r=c.getBoundingClientRect();
      c.style.setProperty("--mx",(e.clientX-r.left)+"px");c.style.setProperty("--my",(e.clientY-r.top)+"px");
    });
  });
})();

/* particle network */
(function(){
  if(reduce)return;
  var cv=document.getElementById("ldFx"),x=cv.getContext("2d"),W,H,P=[],m={x:-999,y:-999};
  function size(){W=cv.width=innerWidth;H=cv.height=innerHeight;var n=Math.min(70,Math.floor(W/22));P=[];for(var i=0;i<n;i++)P.push({x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.5,vy:(Math.random()-.5)*.5});}
  size();addEventListener("resize",size);
  addEventListener("mousemove",function(e){m.x=e.clientX;m.y=e.clientY;});
  (function draw(){
    if(isHidden()){setTimeout(draw,500);return;}
    x.clearRect(0,0,W,H);
    for(var i=0;i<P.length;i++){
      var p=P[i];p.x+=p.vx;p.y+=p.vy;
      if(p.x<0||p.x>W)p.vx*=-1;if(p.y<0||p.y>H)p.vy*=-1;
      var dx=p.x-m.x,dy=p.y-m.y,d=Math.sqrt(dx*dx+dy*dy);
      if(d<110){p.x+=dx/d*1.4;p.y+=dy/d*1.4;}
      x.fillStyle="rgba(56,189,248,.7)";x.beginPath();x.arc(p.x,p.y,1.7,0,6.283);x.fill();
      for(var j=i+1;j<P.length;j++){
        var q=P[j],a=p.x-q.x,b=p.y-q.y,dd=Math.sqrt(a*a+b*b);
        if(dd<125){x.strokeStyle="rgba(56,189,248,"+(.22*(1-dd/125))+")";x.beginPath();x.moveTo(p.x,p.y);x.lineTo(q.x,q.y);x.stroke();}
      }
    }
    requestAnimationFrame(draw);
  })();
})();


/* ---------------------------------------------------------------------
   Light / dark theme toggle for the landing page and the login screen.
   Uses the same storage key and applyTheme() as the dashboards (script.js),
   so one choice applies everywhere.
   --------------------------------------------------------------------- */
(function () {
  var THEME_STORAGE_KEY = "vulenser_theme";   /* same key used by script.js */
  var ICONS =
    '<svg class="ic-sun" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/>' +
    '<path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>' +
    '<svg class="ic-moon" viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';

  function currentTheme() {
    return document.documentElement.dataset.theme === "light" ? "light" : "dark";
  }

  function setTheme(next) {
    if (typeof window.applyTheme === "function") {
      window.applyTheme(next);               /* defined in script.js */
    } else {                                  /* fallback if script.js is not available */
      document.documentElement.dataset.theme = next;
      try { localStorage.setItem(THEME_STORAGE_KEY, next); } catch (e) {}
    }
  }

  function makeButton() {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "ld-theme-btn";
    b.innerHTML = ICONS;
    function sync() {
      var light = currentTheme() === "light";
      b.setAttribute("aria-label", light ? "Switch to dark mode" : "Switch to light mode");
      b.title = light ? "Switch to dark mode" : "Switch to light mode";
    }
    b.addEventListener("click", function () {
      setTheme(currentTheme() === "dark" ? "light" : "dark");
    });
    /* keep the label correct when the theme is changed from anywhere */
    new MutationObserver(sync).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    sync();
    return b;
  }

  /* landing page: before the Sign In button */
  var nc = landing.querySelector(".nc");
  if (nc) nc.insertBefore(makeButton(), nc.firstChild);

  /* login screen: top-right, next to the sound button */
  var shell = document.getElementById("authShell");
  if (shell) shell.appendChild(makeButton());
})();
