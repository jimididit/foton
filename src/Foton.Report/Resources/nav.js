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