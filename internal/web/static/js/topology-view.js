(function(){
  'use strict';
  // The world retains readable node dimensions; only this viewport is scaled.
  // View controls never call the AD mutation API or change connection endpoints.
  window.sambaadmTopologyViewport=function(map,width,height){
    const ru=document.documentElement.lang==='ru',t=(a,b)=>ru?a:b;
    const el=(tag,text='')=>{const element=document.createElement(tag);element.textContent=text;return element;};
    const wrap=el('section'),tools=el('div');tools.className='topology-controls';
    const viewport=el('div');viewport.className='topology-viewport';viewport.tabIndex=0;
    viewport.setAttribute('aria-label',t('Масштабируемая схема контроллеров','Zoomable controller topology'));
    const search=el('input');search.type='search';search.placeholder=t('Найти контроллер','Find controller');search.setAttribute('aria-label',search.placeholder);
    const site=el('select');site.setAttribute('aria-label',t('Фильтр по сайту','Site filter'));
    const all=el('option',t('Все сайты','All sites'));all.value='';site.append(all);
    const nodes=Array.from(map.querySelectorAll('.topology-node')),edges=Array.from(map.querySelectorAll('polyline'));
    for(const name of [...new Set(nodes.map(n=>n.dataset.site).filter(Boolean))].sort()){
      const option=el('option',name);option.value=name;site.append(option);
    }
    const focus=el('input');focus.type='checkbox';focus.setAttribute('role','switch');focus.checked=nodes.length>20;
    const label=el('label',t('Связи выбранного DC','Selected DC connections'));label.prepend(focus);
    const info=el('output'),hint=el('p');hint.className='muted';info.setAttribute('aria-live','polite');
    let scale=1,x=0,y=0,selected='',autoFit=true,visibleCount=nodes.length,pan=null;
    const button=(text,name,action)=>{
      const b=el('button',text);b.type='button';b.setAttribute('aria-label',name);b.title=name;b.addEventListener('click',action);return b;
    };
    function apply(){
      map.style.transform=`translate(${x}px, ${y}px) scale(${scale})`;
      info.textContent=(scale<.01?(scale*100).toFixed(2):Math.round(scale*100))+'% · DC: '+visibleCount+'/'+nodes.length;
    }
    function zoom(factor,px=viewport.clientWidth/2,py=viewport.clientHeight/2){
      const minimum=Math.min(.05,viewport.clientWidth/width/2,viewport.clientHeight/height/2);
      const next=Math.min(4,Math.max(minimum,scale*factor));
      x=px-(px-x)*next/scale;y=py-(py-y)*next/scale;scale=next;autoFit=false;apply();
    }
    function fit(){
      let left=Infinity,right=-Infinity,top=Infinity,bottom=-Infinity;
      for(const n of nodes){
        if(n.hidden)continue;
        left=Math.min(left,+n.dataset.x-110);right=Math.max(right,+n.dataset.x+110);
        top=Math.min(top,+n.dataset.y-50);bottom=Math.max(bottom,+n.dataset.y+50);
      }
      if(!Number.isFinite(left)){left=0;right=width;top=0;bottom=height;}
      if(viewport.clientWidth<1||viewport.clientHeight<1)return;
      scale=Math.min(1.5,(viewport.clientWidth-24)/(right-left),(viewport.clientHeight-24)/(bottom-top));
      x=(viewport.clientWidth-(left+right)*scale)/2;y=(viewport.clientHeight-(top+bottom)*scale)/2;
      autoFit=true;apply();
    }
    function filter(refit){
      const needle=search.value.trim().toLocaleLowerCase(),visible=new Set();
      for(const n of nodes){
        const show=(!site.value||n.dataset.site===site.value)&&(!needle||(n.dataset.dc+' '+n.textContent).toLocaleLowerCase().includes(needle));
        n.hidden=!show;n.classList.toggle('focused',n.dataset.dc===selected);
        n.setAttribute('aria-pressed',String(n.dataset.dc===selected));
        if(show)visible.add(n.dataset.dc.toLowerCase());
      }
      visibleCount=visible.size;
      for(const edge of edges){
        const a=edge.dataset.source,b=edge.dataset.destination;
        // SVG does not implement the HTML hidden property.
        edge.style.display=visible.has(a)&&visible.has(b)&&(!focus.checked||!!selected&&(a===selected.toLowerCase()||b===selected.toLowerCase()))?'':'none';
      }
      hint.textContent=!visibleCount?t('Контроллеры не найдены','No controllers found'):
        focus.checked&&!visible.has(selected.toLowerCase())?t('Выберите контроллер на схеме, чтобы увидеть его связи.','Select a controller on the map to see its connections.'):
        t('Масштаб: кнопки или Ctrl + колесо. Перемещение: перетащите фон.','Zoom with buttons or Ctrl + wheel. Drag the background to pan.');
      if(refit)fit();else apply();
    }
    tools.append(search,site,
      button('−',t('Уменьшить масштаб','Zoom out'),()=>zoom(1/1.25)),
      button('+',t('Увеличить масштаб','Zoom in'),()=>zoom(1.25)),
      button('100%',t('Исходный масштаб','Actual size'),()=>zoom(1/scale)),
      button(t('Вписать целиком','Fit to view'),t('Вписать целиком','Fit to view'),fit),label,info);
    wrap.append(tools,hint,viewport);viewport.append(map);
    Object.assign(map.style,{width:width+'px',height:height+'px',aspectRatio:'auto',margin:'0',transformOrigin:'0 0'});
    for(const n of nodes)n.addEventListener('click',()=>{selected=n.dataset.dc;filter(false);});
    search.addEventListener('input',()=>filter(true));site.addEventListener('change',()=>filter(true));focus.addEventListener('change',()=>filter(false));
    viewport.addEventListener('wheel',e=>{
      if(!e.ctrlKey&&!e.metaKey)return;
      e.preventDefault();const rect=viewport.getBoundingClientRect();zoom(e.deltaY<0?1.15:1/1.15,e.clientX-rect.left,e.clientY-rect.top);
    },{passive:false});
    viewport.addEventListener('pointerdown',e=>{
      if(e.button!==0||e.target.closest('button'))return;
      pan={id:e.pointerId,px:e.clientX,py:e.clientY,x,y};viewport.setPointerCapture(e.pointerId);
    });
    viewport.addEventListener('pointermove',e=>{
      if(!pan||e.pointerId!==pan.id)return;
      x=pan.x+e.clientX-pan.px;y=pan.y+e.clientY-pan.py;autoFit=false;apply();
    });
    for(const event of ['pointerup','pointercancel','lostpointercapture'])viewport.addEventListener(event,()=>{pan=null;});
    viewport.addEventListener('keydown',e=>{
      if(e.target!==viewport)return;
      const moves={ArrowLeft:[40,0],ArrowRight:[-40,0],ArrowUp:[0,40],ArrowDown:[0,-40]};
      if(moves[e.key]){e.preventDefault();autoFit=false;x+=moves[e.key][0];y+=moves[e.key][1];apply();}
      else if(['+','=','-','0'].includes(e.key)){e.preventDefault();if(e.key==='0')fit();else zoom(e.key==='-'?1/1.25:1.25);}
    });
    // Tabbing to a node also brings it into view at the current scale.
    viewport.addEventListener('focusin',e=>{
      const n=e.target.closest('.topology-node');if(!n)return;
      const rect=n.getBoundingClientRect(),bounds=viewport.getBoundingClientRect();
      if(rect.left<bounds.left||rect.right>bounds.right||rect.top<bounds.top||rect.bottom>bounds.bottom){
        x=viewport.clientWidth/2-(+n.dataset.x)*scale;y=viewport.clientHeight/2-(+n.dataset.y)*scale;autoFit=false;apply();
      }
    });
    let dialog=null;
    const dispose=()=>{observer.disconnect();dialog?.removeEventListener('close',dispose);};
    const observer=new ResizeObserver(()=>{if(!viewport.isConnected)dispose();else if(autoFit)fit();});
    requestAnimationFrame(()=>{
      if(!viewport.isConnected)return;
      filter(false);fit();observer.observe(viewport);dialog=map.closest('dialog');dialog?.addEventListener('close',dispose,{once:true});
    });
    return wrap;
  };
})();
