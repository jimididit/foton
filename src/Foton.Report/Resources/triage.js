<script>
(function(){
  document.addEventListener("click",function(e){
    var h=e.target.closest(".f-head");
    if(h){h.parentElement.classList.toggle("open");return;}
    var b=e.target.closest(".btn[data-sev]");
    if(b){
      document.querySelectorAll(".btn[data-sev]").forEach(function(x){x.classList.remove("on")});
      b.classList.add("on");
      applyFilters();
    }
  });
  var box=document.getElementById("foton-q");
  if(box){box.addEventListener("input",applyFilters);}
  function applyFilters(){
    var active=document.querySelector(".btn[data-sev].on");
    var sev=active?active.getAttribute("data-sev"):"all";
    var q=(box&&box.value||"").toLowerCase();
    var shown=0;
    document.querySelectorAll(".finding").forEach(function(f){
      var okSev=(sev==="all"||f.getAttribute("data-sev")===sev);
      var okQ=(q===""||f.textContent.toLowerCase().indexOf(q)>-1);
      if(okSev&&okQ){f.classList.remove("hidden");shown++;}else{f.classList.add("hidden");}
    });
    var none=document.getElementById("nores");
    if(none){none.style.display=shown?"none":"block";}
  }
  document.querySelectorAll(".finding").forEach(function(f){
    if(f.getAttribute("data-sev")==="High"){f.classList.add("open");}
  });
})();
</script>