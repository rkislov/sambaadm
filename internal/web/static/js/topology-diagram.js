(function(){
  'use strict';
  const nodeWidth=180,nodeHeight=62,padding=24,gap=28;
  const svgNS='http://www.w3.org/2000/svg';
  const key=name=>(name||'').toLowerCase();
  const clamp=(n,min,max)=>Math.max(min,Math.min(n,max));
  const point=(x,y)=>({x,y});
  const contains=(box,p)=>p.x>=box.x&&p.y>=box.y&&p.x<=box.x+box.width&&p.y<=box.y+box.height;
  const cellCenter=box=>point(box.x+box.width/2,box.y+box.height/2);
  function svg(tag,attrs={}){
    const element=document.createElementNS(svgNS,tag);
    for(const [name,value] of Object.entries(attrs))element.setAttribute(name,value);
    return element;
  }
  function border(box,target){
    const center=cellCenter(box),dx=target.x-center.x,dy=target.y-center.y;
    const scale=Math.max(Math.abs(dx)/(box.width/2),Math.abs(dy)/(box.height/2),.001);
    return point(center.x+dx/scale,center.y+dy/scale);
  }
  function domainTrusts(data,t){
    const direction={
      '0':[false,false,t('Отключено','Disabled')],
      '1':[true,false,t('Входящее','Inbound')],
      '2':[false,true,t('Исходящее','Outbound')],
      '3':[true,true,t('Двустороннее','Bidirectional')]
    };
    const directionCodes={inbound:'1',outbound:'2',bidirectional:'3',disabled:'0'};
    const types={
      external:t('Внешнее','External'),
      forest:t('Межлесное','Forest'),
      within_forest:t('Внутри леса','Within forest'),
      windows_ad:'Windows AD',
      windows_non_ad:t('Windows без AD','Windows without AD'),
      mit:'MIT Kerberos',
      dormant:t('Неактивный тип','Dormant type')
    };
    const rows=[...(data.trusts||[])].sort((a,b)=>a.domain.localeCompare(b.domain)).map(trust=>{
      const [left,right,label]=direction[trust.rawDirection||directionCodes[trust.direction]]||
        [false,false,t('Направление неизвестно','Unknown direction')];
      const type=types[trust.scope||trust.type]||t('Тип неизвестен','Unknown type');
      return {partner:trust.domain,left,right,label:label+' · '+type};
    });
    return {
      local:data.domain||t('Текущий домен','Current domain'),
      title:t('Доверительные отношения','Domain trusts'),
      legend:t('Стрелка направлена от доверяющего домена к доверенному. Показаны настройки текущего домена.','Arrows point from the trusting domain to the trusted domain. The diagram shows the current domain configuration.'),
      status:data.trustError||(rows.length?'':t('Доверительные отношения не настроены','No domain trusts configured')),
      rows
    };
  }
  function trustPanel(model,el){
    const panel=el('details','topology-trusts');panel.open=model.rows.length>0;
    panel.append(el('summary','',model.title+(model.rows.length?' · '+model.rows.length:'')));
    if(model.status){
      panel.open=true;
      panel.append(el('p','muted',model.status));
      return panel;
    }
    panel.append(el('p','muted',model.legend));
    const list=el('ul','topology-trust-list');
    for(const trust of model.rows){
      const row=el('li','topology-trust-row');
      const relation=el('div','topology-trust-relation');
      const arrow=el('span','topology-trust-arrow',trust.left?(trust.right?'↔':'←'):(trust.right?'→':'—'));
      arrow.setAttribute('aria-hidden','true');
      relation.append(arrow,el('span','',trust.label));
      row.append(el('strong','topology-trust-domain',model.local),relation,el('strong','topology-trust-domain',trust.partner));
      list.append(row);
    }
    panel.append(list);
    return panel;
  }
  function exportDiagram(sites,nodes,links,edges,unmapped,trusts,{t}){
    const xml=document.implementation.createDocument(null,'mxfile');
    function append(parent,tag,attrs={}){
      const element=xml.createElement(tag);
      for(const [name,value] of Object.entries(attrs))element.setAttribute(name,String(value).replace(/[^\u0009\u000a\u000d\u0020-\ud7ff\ue000-\ufffd\u{10000}-\u{10ffff}]/gu,''));
      parent.append(element);
      return element;
    }
    function sheet(id,name){
      const diagram=append(xml.documentElement,'diagram',{id,name});
      const graph=append(diagram,'mxGraphModel',{grid:1,gridSize:10,page:0,connect:1,arrows:1});
      const root=append(graph,'root');
      append(root,'mxCell',{id:0});append(root,'mxCell',{id:1,parent:0});
      return root;
    }
    let root=sheet('ad-topology',t('Топология AD','AD topology'));
    function vertex(id,parent,value,box,style,tooltip=''){
      const wrapper=tooltip?append(root,'object',{id,label:value,tooltip}):root;
      const attrs=tooltip?{}:{id,value};
      const cell=append(wrapper,'mxCell',{...attrs,parent,vertex:1,style:'html=0;whiteSpace=wrap;'+style});
      append(cell,'mxGeometry',{x:Math.round(box.x),y:Math.round(box.y),width:box.width,height:box.height,as:'geometry'});
    }
    function edge(id,from,to,value,style,waypoint){
      const cell=append(root,'mxCell',{id,parent:1,source:from.id,target:to.id,value,edge:1,style:'html=0;labelBackgroundColor=#ffffff;'+style});
      const geometry=append(cell,'mxGeometry',{relative:1,as:'geometry'});
      if(waypoint)append(append(geometry,'Array',{as:'points'}),'mxPoint',{x:Math.round(waypoint.x),y:Math.round(waypoint.y)});
    }
    for(const site of sites){
      vertex(site.id,1,site.label,site,'rounded=1;container=1;recursiveResize=0;verticalAlign=top;align=left;spacingLeft=14;spacingTop=10;fontStyle=1;fillColor=#eaf1f8;strokeColor=#91a8bc;');
      if(site.subnets.length){
        const label=site.subnets.length<=3?site.subnets.join(' · '):t('Подсети','Subnets')+' · '+site.subnets.length;
        vertex(site.id+'-subnets',site.id,label,{x:12,y:36,width:site.width-24,height:36},
          'fillColor=none;strokeColor=none;align=left;fontSize=11;fontColor=#395772;',site.subnets.join(' · '));
      }
    }
    for(const item of nodes){
      vertex(item.id,item.site.id,item.dc.dns+'\n'+item.role,item.local,'rounded=1;fillColor=#ffffff;strokeWidth=2;strokeColor='+(item.dc.rodc?'#a36318':'#256678')+';');
    }
    for(const link of links){
      vertex(link.id,1,link.label,link,'rounded=1;fillColor=#f3efff;strokeColor=#73629c;');
      link.sites.forEach((site,index)=>edge(link.id+'-'+index,link,site,'','dashed=1;dashPattern=2 4;strokeColor=#73629c;endArrow=none;'));
    }
    edges.forEach((item,index)=>edge('replication-'+index,item.from,item.to,item.connection.automatic?'KCC':'',
      'strokeColor=#256678;endArrow=block;endFill=1;'+(item.connection.enabled?'':'dashed=1;'),item.offset?midpoint(item):null));
    if(unmapped.length){
      const value=[t('Объекты вне схемы','Objects outside the diagram'),...unmapped].join('\n');
      const bottom=Math.max(0,...sites.map(s=>s.y+s.height),...links.map(l=>l.y+l.height));
      vertex('unmapped',1,value,{x:40,y:bottom+44,width:480,height:40+unmapped.length*20},'rounded=1;fillColor=#fff4dd;strokeColor=#a36318;align=left;spacing=12;');
    }
    root=sheet('domain-trusts',trusts.title);
    vertex('trust-heading',1,trusts.legend,{x:36,y:24,width:780,height:48},'strokeColor=none;fillColor=none;align=left;');
    const trustShape='rounded=1;strokeColor=#28625b;fontStyle=1;';
    const local={id:'trust-local',x:36,y:88+Math.max(0,trusts.rows.length-1)*50,width:230,height:62};
    vertex(local.id,1,trusts.local,local,trustShape+'fillColor=#dcefea;');
    for(const [index,trust] of trusts.rows.entries()){
      const partner={id:'trust-partner-'+index,x:560,y:88+index*100,width:230,height:62};
      vertex(partner.id,1,trust.partner,partner,trustShape+'fillColor=#f1f8f7;');
      const arrows='startArrow='+(trust.left?'block':'none')+';endArrow='+(trust.right?'block':'none')+';';
      edge('trust-edge-'+index,local,partner,trust.label,
        'strokeColor=#28625b;strokeWidth=2;startFill=1;endFill=1;'+arrows+(!trust.left&&!trust.right?'dashed=1;':''));
    }
    if(trusts.status)vertex('trust-status',1,trusts.status,{x:306,y:86,width:480,height:68},
      'rounded=1;fillColor=#fff4dd;strokeColor=#a36318;align=left;spacing=12;');
    const url=URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(xml)],{type:'application/xml;charset=utf-8'}));
    const anchor=document.createElement('a');
    anchor.href=url;anchor.download='ad-topology.drawio';document.body.append(anchor);anchor.click();anchor.remove();
    setTimeout(()=>URL.revokeObjectURL(url),30_000);
  }
  function midpoint({from,to,offset}){
    const a=cellCenter(from),b=cellCenter(to),dx=b.x-a.x,dy=b.y-a.y,length=Math.hypot(dx,dy)||1;
    return point((a.x+b.x)/2-dy/length*offset,(a.y+b.y)/2+dx/length*offset);
  }
  window.sambaadmTopologyDiagram=function(data,{t,el,button,onSelect,onSiteDrop,onConnectDrop,layout,exportWarnings=[]}){
    const map=el('div','topology-map topology-diagram');
    const graph=svg('svg',{'aria-hidden':'true'});
    const defs=svg('defs');
    const marker=svg('marker',{id:'ad-replication-arrow',viewBox:'0 0 10 10',refX:9,refY:5,markerWidth:7,markerHeight:7,orient:'auto'});
    marker.append(svg('path',{d:'M0 0 L10 5 L0 10 Z',fill:'#256678'}));defs.append(marker);
    const siteWires=svg('g'),replicationWires=svg('g');
    graph.append(defs,siteWires,replicationWires);
    map.append(graph);
    const grouped=new Map(),siteByDN=new Map(),nodeByDNS=new Map(),nodes=[],links=[],edges=[],unmapped=[];
    function group(name){
      const id=key(name);
      if(!grouped.has(id))grouped.set(id,{id:'site-'+grouped.size,name,controllers:[],subnets:[],attached:new Set()});
      return grouped.get(id);
    }
    for(const site of data.sites||[]){
      const item=group(site.name);
      item.registered=true;
      if(site.dn)siteByDN.set(key(site.dn),item);
    }
    for(const dc of data.controllers)group(dc.site||'').controllers.push(dc);
    for(const subnet of data.subnets||[]){
      const site=siteByDN.get(key(subnet.site))||grouped.get(key(subnet.site));
      if(subnet.site&&site)site.subnets.push(subnet.name);
      else unmapped.push(subnet.name+(subnet.site?' · '+subnet.site:' · '+t('без сайта','no site')));
    }
    const sites=[...grouped.values()].sort((a,b)=>a.name.localeCompare(b.name));
    for(const site of sites){
      site.subnets.sort();
      site.label=site.name||t('Без сайта','No site');
      site.header=site.subnets.length?78:50;
      const count=site.controllers.length;
      site.columns=Math.max(1,Math.ceil(Math.sqrt(count*.75)));
      site.width=Math.max(270,padding*2+site.columns*(nodeWidth+gap)-gap);
      site.height=site.header+padding+Math.max(1,Math.ceil(count/site.columns))*(nodeHeight+gap)-gap+26;
    }
    const rowWidth=Math.max(720,...sites.map(s=>s.width+80),Math.sqrt(sites.reduce((sum,s)=>sum+(s.width+145)*(s.height+135),0)*1.8));
    let x=40,y=40,rowHeight=0;
    function place(item,id){
      if(x>40&&x+item.width>rowWidth){x=40;y+=rowHeight+110;rowHeight=0;}
      item.initial=point(x,y);
      Object.assign(item,layout.get(id)||item.initial);
      x+=item.width+120;
      rowHeight=Math.max(rowHeight,item.height);
    }
    const handle=(label,className)=>{
      const element=el('button',className,label);element.type='button';return element;
    };
    for(const site of sites){
      site.layoutID='site:'+key(site.name);
      place(site,site.layoutID);
      site.frame=el('div','topology-site-frame');
      site.frame.dataset.site=site.name;
      site.headerButton=handle(site.label,'topology-site-heading');
      site.frame.append(site.headerButton);
      if(site.subnets.length){
        const subnets=el('div','topology-site-subnets',site.subnets.join(' · '));subnets.title=site.subnets.join('\n');site.frame.append(subnets);
      }
      map.append(site.frame);
      site.nodes=site.controllers.map((dc,index)=>{
        const id=key(dc.dns),layoutID='dc:'+id;
        const initial=point(padding+(index%site.columns)*(nodeWidth+gap)+13,site.header+13+Math.floor(index/site.columns)*(nodeHeight+gap));
        const saved=layout.get(layoutID);
        const local={...(saved?.site===key(site.name)?saved:initial),width:nodeWidth,height:nodeHeight};
        local.x=clamp(local.x,8,site.width-nodeWidth-8);
        local.y=clamp(local.y,site.header,site.height-nodeHeight-8);
        const role=typeof dc.rodc==='boolean'?(dc.rodc?'RODC':'RWDC'):t('Контроллер домена','Domain controller');
        const element=handle('','topology-node');
        element.append(el('span','topology-node-name',dc.name||dc.dns),el('span','topology-node-role',role));
        Object.assign(element.dataset,{dc:dc.dns,site:site.name,role});
        element.title=dc.dns+' · '+role;
        map.append(element);
        const item={id:'dc-'+nodes.length,dc,role,element,site,local,initial,layoutID,width:nodeWidth,height:nodeHeight,attached:new Set()};
        nodes.push(item);nodeByDNS.set(id,item);
        return item;
      });
    }
    if(sites.length){x=40;y+=rowHeight+95;rowHeight=0;}
    for(const link of data.links){
      const members=[...new Set(link.sites||[])].map(name=>[name,grouped.get(key(name))]);
      for(const [name,site] of members)if(!site)unmapped.push(link.name+' → '+name);
      const label=link.name+'\n'+t('Стоимость ','Cost ')+link.cost+' · '+link.interval+' '+t('мин','min');
      const item={id:'link-'+links.length,layoutID:'link:'+key(link.dn||link.name),label,
        sites:members.map(([,site])=>site).filter(Boolean),width:190,height:58,attached:new Set()};
      place(item,item.layoutID);
      item.element=handle(label,'topology-site-link');
      item.element.title=members.map(([name])=>name).join(' · ');
      map.append(item.element);
      links.push(item);
      for(const site of item.sites){
        const line=svg('line',{class:'topology-site-wire'});
        const update=()=>{
          const a=border(item,cellCenter(site)),b=border(site,cellCenter(item));
          for(const [name,value] of Object.entries({x1:a.x,y1:a.y,x2:b.x,y2:b.y}))line.setAttribute(name,value);
        };
        siteWires.append(line);item.attached.add(update);site.attached.add(update);
      }
    }
    const pairKey=(a,b)=>JSON.stringify([key(a),key(b)]);
    const pairCounts=new Map(),pairIndex=new Map();
    for(const {source,destination} of data.connections){
      const pair=pairKey(source,destination);
      pairCounts.set(pair,(pairCounts.get(pair)||0)+1);
    }
    for(const connection of data.connections){
      const {source,destination}=connection;
      const from=nodeByDNS.get(key(source)),to=nodeByDNS.get(key(destination));
      if(!from||!to||from===to){unmapped.push(source+' → '+destination);continue;}
      const pair=pairKey(source,destination),index=pairIndex.get(pair)||0;
      pairIndex.set(pair,index+1);
      const reverse=pairCounts.has(pairKey(destination,source));
      const offset=reverse?14+index*12:(index-(pairCounts.get(pair)-1)/2)*14;
      const item={connection,from,to,offset};
      const line=svg('polyline',{class:'topology-replication-wire','stroke-dasharray':connection.enabled?'':'7 5','marker-end':'url(#ad-replication-arrow)'});
      Object.assign(line.dataset,{source:key(connection.source),destination:key(connection.destination)});
      const hint=svg('title');
      hint.textContent=connection.source+' → '+connection.destination+(connection.automatic?' · KCC':'');
      line.append(hint);replicationWires.append(line);
      const update=()=>{
        const middle=midpoint(item),a=border(from,middle),b=border(to,middle);
        line.setAttribute('points',`${a.x},${a.y} ${middle.x},${middle.y} ${b.x},${b.y}`);
      };
      from.attached.add(update);to.attached.add(update);edges.push(item);
    }
    function box(element,item){
      Object.assign(element.dataset,{x:item.x,y:item.y,width:item.width,height:item.height});
      Object.assign(element.style,{left:item.x+'px',top:item.y+'px',width:item.width+'px',height:item.height+'px'});
    }
    function drawNode(item,position=item.local){
      item.x=item.site.x+position.x;item.y=item.site.y+position.y;
      const center=cellCenter(item);
      box(item.element,item);
      Object.assign(item.element.dataset,center);
    }
    function drawSite(site){
      box(site.frame,site);
      site.nodes.forEach(item=>drawNode(item));
      for(const item of site.nodes)item.attached.forEach(update=>update());
      site.attached.forEach(update=>update());
    }
    function drawLink(link){box(link.element,link);link.attached.forEach(update=>update());}
    sites.forEach(drawSite);links.forEach(drawLink);
    const width=Math.max(720,...sites.map(s=>s.x+s.width+40),...links.map(l=>l.x+l.width+40));
    const height=Math.max(180,...sites.map(s=>s.y+s.height+40),...links.map(l=>l.y+l.height+40));
    graph.setAttribute('viewBox',`0 0 ${width} ${height}`);
    const view=window.sambaadmTopologyViewport(map,width,height);
    const controls=view.querySelector('.topology-controls');
    const trusts=domainTrusts(data,t);
    view.insertBefore(trustPanel(trusts,el),view.querySelector('.topology-viewport'));
    let mode='layout',active=null;
    if(onSiteDrop){
      const select=el('select');select.setAttribute('aria-label',t('Действие при перетаскивании','Drag action'));
      for(const [value,label] of [['layout',t('Раскладка схемы','Diagram layout')],['site',t('Перенос DC между сайтами AD','Move DC between AD sites')],['connect',t('Создание соединения','Create connection')]]){
        const option=el('option','',label);option.value=value;select.append(option);
      }
      controls.append(select);
      select.addEventListener('change',()=>{mode=select.value;map.classList.toggle('topology-move-mode',mode==='site');});
    }
    controls.append(button(t('Скачать .drawio','Download .drawio'),()=>{
      if(!active)exportDiagram(sites,nodes,links,edges,[...exportWarnings,...unmapped],trusts,{t});
    }));
    const reset=button(t('Сбросить раскладку','Reset layout'),()=>{
      layout.clear();
      for(const site of sites){
        Object.assign(site,site.initial);
        site.nodes.forEach(item=>Object.assign(item.local,item.initial));
        drawSite(site);
      }
      for(const link of links){Object.assign(link,link.initial);drawLink(link);}
      view.dispatchEvent(new Event('topology-fit'));
    });
    controls.append(reset);
    const viewport=view.querySelector('.topology-viewport');
    const world=(cx,cy)=>{
      const rect=map.getBoundingClientRect(),scale=rect.width/map.offsetWidth;
      return point((cx-rect.left)/scale,(cy-rect.top)/scale);
    };
    function draggable(handle,item,draw,position,onDrop){
      let suppressClick=false;
      handle.addEventListener('pointerdown',e=>{
        if(e.button!==0||active)return;
        suppressClick=false;
        active={id:e.pointerId,mouse:world(e.clientX,e.clientY),start:point(position.x,position.y),moved:false,mode:item.dc?(mode==='site'&&!item.dc.revision?'layout':mode):'layout'};
        handle.setPointerCapture(e.pointerId);
      });
      handle.addEventListener('pointermove',e=>{
        if(!active||active.id!==e.pointerId||!handle.hasPointerCapture(e.pointerId))return;
        const cursor=world(e.clientX,e.clientY),dx=cursor.x-active.mouse.x,dy=cursor.y-active.mouse.y;
        if(!active.moved&&Math.hypot(dx,dy)*map.getBoundingClientRect().width/map.offsetWidth<5)return;
        active.moved=true;suppressClick=true;
        handle.classList.add('topology-dragging');
        draw(point(active.start.x+dx,active.start.y+dy),active.mode!=='layout');
        if(active.mode==='site'){
          active.target=sites.filter(site=>site!==item.site&&site.registered&&!site.frame.hidden&&contains(site,cursor)).at(-1);
          sites.forEach(site=>site.frame.classList.toggle('topology-drop-target',site===active.target));
        }else if(active.mode==='connect'){
          active.target=nodes.filter(other=>other!==item&&!other.element.hidden&&contains(other,cursor)).at(-1);
          nodes.forEach(other=>other.element.classList.toggle('topology-drop-target',other===active.target));
        }
      });
      function finish(e){
        if(!active||active.id!==e.pointerId||e.target!==handle)return;
        const gesture=active;active=null;
        handle.classList.remove('topology-dragging');
        if(gesture.moved&&(e.type!=='pointerup'||gesture.mode!=='layout'))draw(gesture.start,false);
        sites.forEach(site=>site.frame.classList.remove('topology-drop-target'));
        if(gesture.mode==='connect')nodes.forEach(other=>other.element.classList.remove('topology-drop-target'));
        if(e.type==='pointerup'&&gesture.moved){
          if(gesture.mode==='layout')save();
          else if(gesture.target)onDrop(gesture.mode,gesture.target);
        }
      }
      const save=()=>layout.set(item.layoutID,{x:position.x,y:position.y,site:item.site?key(item.site.name):undefined});
      for(const event of ['pointerup','pointercancel','lostpointercapture'])handle.addEventListener(event,finish);
      handle.addEventListener('click',e=>{
        if(!suppressClick||e.detail===0)return;
        e.preventDefault();e.stopImmediatePropagation();suppressClick=false;
      },true);
      handle.addEventListener('keydown',e=>{
        const delta={ArrowLeft:[-16,0],ArrowRight:[16,0],ArrowUp:[0,-16],ArrowDown:[0,16]}[e.key];
        if(!delta)return;
        e.preventDefault();
        draw(point(position.x+delta[0],position.y+delta[1]),false);save();
      });
    }
    for(const item of [...sites,...links]){
      draggable(item.headerButton||item.element,item,position=>{
        item.x=Math.max(12,position.x);item.y=Math.max(12,position.y);
        item.headerButton?drawSite(item):drawLink(item);
      },item);
    }
    for(const item of nodes){
      draggable(item.element,item,(position,preview)=>{
        if(!preview){
          item.local.x=clamp(position.x,8,item.site.width-nodeWidth-8);
          item.local.y=clamp(position.y,item.site.header,item.site.height-nodeHeight-8);
        }
        drawNode(item,preview?position:item.local);item.attached.forEach(update=>update());
      },item.local,(action,target)=>{if(action==='site')onSiteDrop(item.dc,target.name);else onConnectDrop(item.dc,target.dc);});
      item.element.addEventListener('click',()=>onSelect(item.dc));
    }
    viewport.classList.add('topology-editor-viewport');
    return {view,map,unmapped};
  };
})();
