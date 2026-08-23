function Get-FotonReportSectionId {
    param([string]$Name)
    $s = [regex]::Replace([string]$Name, '[^A-Za-z0-9]+', '-')
    $s = $s.Trim('-')
    if (-not $s) { $s = 'section' }
    return ('sec-' + $s)
}

function Get-FotonReportNavCss {
    @'
.foton-bar{position:sticky;top:0;z-index:50;background:rgba(11,16,22,.94);backdrop-filter:blur(8px);border:1px solid var(--line);border-radius:12px;padding:10px 14px;margin:16px 0 8px}
.foton-bar-row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.foton-bar input[type=search]{flex:1;min-width:200px;background:var(--panel2);border:1px solid var(--line);border-radius:20px;color:var(--text);padding:8px 14px;font-size:13px}
.foton-bar .foton-stat{color:#7f93a8;font-size:12px;white-space:nowrap}
.foton-bar a.foton-top{color:var(--beam);font-size:12px;text-decoration:none;border:1px solid var(--line);border-radius:20px;padding:6px 12px}
.foton-bar a.foton-top:hover{border-color:var(--beam)}
.controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:12px 0}
.btn{background:var(--panel);border:1px solid var(--line);color:#b9cadb;border-radius:20px;padding:6px 15px;font-size:12.5px;cursor:pointer}
.btn:hover{border-color:var(--beam);color:#fff}
.btn.on{background:rgba(55,214,255,.14);border-color:var(--beam);color:#fff}
.foton-toc{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;max-height:5.6em;overflow:auto}
.foton-toc a{font-size:11px;color:#8fa3b8;border:1px solid var(--line);border-radius:999px;padding:3px 10px;text-decoration:none;white-space:nowrap}
.foton-toc a:hover,.foton-toc a:focus{color:var(--beam);border-color:var(--beam)}
.foton-sec.foton-hidden,.foton-hide{display:none!important}
a.card{text-decoration:none;color:inherit;display:block}
a.card:hover{border-color:var(--beam)}
html{scroll-behavior:smooth;scroll-padding-top:84px}
'@
}

function Get-FotonReportNavBarHtml {
    @'
<div class="foton-bar" id="foton-bar">
  <div class="foton-bar-row">
    <input id="foton-q" type="search" placeholder="Filter this report (tables, findings, section titles)" autocomplete="off">
    <span class="foton-stat" id="foton-stat"></span>
    <a class="foton-top" href="#top">Top</a>
  </div>
  <nav class="foton-toc" id="foton-toc" aria-label="Jump to section"></nav>
</div>
'@
}

function Get-FotonReportNavScript {
    @'
<script>
(function(){
  var qBox=document.getElementById("foton-q");
  var toc=document.getElementById("foton-toc");
  var stat=document.getElementById("foton-stat");
  var heads=[].slice.call(document.querySelectorAll("h2"));
  function slug(t,i){
    var s=(t||"").replace(/<[^>]+>/g," ").replace(/[^A-Za-z0-9]+/g,"-").replace(/^-|-$/g,"");
    return "sec-"+(s||("n"+i));
  }
  function titleOf(h){
    var n=h.cloneNode(true);
    var sm=n.querySelector("small");
    if(sm) sm.parentNode.removeChild(sm);
    return (n.textContent||"").replace(/\s+/g," ").trim();
  }
  if(toc){
    heads.forEach(function(h,i){
      if(!h.id) h.id=slug(titleOf(h),i);
      var a=document.createElement("a");
      a.href="#"+h.id;
      a.textContent=titleOf(h)||("Section "+(i+1));
      toc.appendChild(a);
    });
  }
  function sectionBits(h){
    var n=h.nextElementSibling, bits=[];
    while(n && n.tagName!=="H2" && !n.classList.contains("foton-bar")){
      bits.push(n);
      n=n.nextElementSibling;
    }
    return bits;
  }
  function apply(){
    var needle=((qBox&&qBox.value)||"").toLowerCase();
    var chBtn=document.querySelector(".btn[data-change].on");
    var ch=chBtn?chBtn.getAttribute("data-change"):"all";
    var rows=0, shown=0;
    document.querySelectorAll("table tbody tr").forEach(function(tr){
      rows++;
      var okQ=!needle||(tr.textContent||"").toLowerCase().indexOf(needle)>-1;
      var okC=true;
      if(ch!=="all" && tr.getAttribute("data-change")) okC=tr.getAttribute("data-change")===ch;
      if(okQ&&okC){tr.classList.remove("foton-hide");shown++;}else{tr.classList.add("foton-hide");}
    });
    heads.forEach(function(h){
      var bits=sectionBits(h);
      var hit=!needle||titleOf(h).toLowerCase().indexOf(needle)>-1;
      if(!hit){
        bits.forEach(function(el){
          if(/table|p|div|details/i.test(el.tagName) && (el.textContent||"").toLowerCase().indexOf(needle)>-1) hit=true;
          el.querySelectorAll("tbody tr").forEach(function(tr){
            if(!tr.classList.contains("foton-hide")) hit=true;
          });
          el.querySelectorAll(".finding").forEach(function(f){
            if(!f.classList.contains("hidden") && !f.classList.contains("foton-hide")) hit=true;
          });
        });
      }
      if(needle && !hit){
        h.classList.add("foton-hide");
        bits.forEach(function(el){el.classList.add("foton-hide");});
      }else{
        h.classList.remove("foton-hide");
        bits.forEach(function(el){el.classList.remove("foton-hide");});
      }
    });
    if(stat){
      if(needle||(ch && ch!=="all")) stat.textContent=shown+" / "+rows+" rows";
      else stat.textContent=heads.length+" sections";
    }
  }
  if(qBox) qBox.addEventListener("input",apply);
  document.addEventListener("click",function(e){
    var b=e.target.closest(".btn[data-change]");
    if(!b) return;
    document.querySelectorAll(".btn[data-change]").forEach(function(x){x.classList.remove("on");});
    b.classList.add("on");
    apply();
  });
  apply();
})();
</script>
'@
}
