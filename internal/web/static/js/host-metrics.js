(function () {
  'use strict';
  const root = document.getElementById('domain-dashboard'); if (!root) return;
  const ru = document.documentElement.lang === 'ru', t = (a,b) => ru ? a : b;
  const el = (tag,text='',cls='') => {const e=document.createElement(tag);e.textContent=text;if(cls)e.className=cls;return e;};
  const section=el('details','','dashboard-details host-metrics'),summary=el('summary'),values=el('span','','host-metric-values'),notice=el('p','','muted'),charts=el('div','','dashboard-cards');
  section.id='host-metrics';summary.append(el('span',t('Нагрузка сервера','Server usage')),values);section.append(summary,notice,charts);root.after(section);
  let timer,stopped=false,latest;
  function draw(){
    charts.replaceChildren();if(!section.open||!latest)return;
    const samples=latest.samples,last=samples.at(-1);
    notice.textContent=latest.host+' · '+t('Обновление каждые 5 секунд','Updates every 5 seconds');
    for(const [key,label] of [['cpu','CPU'],['memory',t('Память','Memory')],['disk',t('Диск','Disk')]]){
      const card=el('div','','dashboard-card');card.append(el('span',label),el('strong',last[key]==null?'—':last[key].toFixed(1)+'%'));
      const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 300 100');svg.setAttribute('role','img');svg.setAttribute('aria-label',label+' 0–100%');
      const start=Math.min(samples[0].time,last.time-60000),range=Math.max(60000,last.time-start);let d='',previous=null;
      for(const sample of samples){if(sample[key]==null){previous=null;continue;}const x=(sample.time-start)/range*300,y=98-Math.max(0,Math.min(100,sample[key]))*.94;d+=(previous&&sample.time-previous<15000?'L':'M')+x.toFixed(1)+' '+y.toFixed(1)+' ';previous=sample.time;}
      const path=document.createElementNS(svg.namespaceURI,'path');path.setAttribute('d',d);path.setAttribute('fill','none');path.setAttribute('stroke','#087c80');path.setAttribute('stroke-width','2');svg.append(path);card.append(svg);charts.append(card);
    }
  }
  async function update(){
    if(stopped)return;
    if(!document.hidden){try{
      const response=await fetch('/api/v1/system/metrics',{credentials:'same-origin',signal:AbortSignal.timeout(6000)});if(!response.ok)throw Error('HTTP '+response.status);
      const data=await response.json(),last=(data.samples||[]).at(-1);if(!last)throw Error(t('Нет замеров','No samples'));latest=data;
      values.textContent=[['cpu','CPU'],['memory',t('Память','Memory')],['disk',t('Диск','Disk')]].map(([key,label])=>label+' '+(last[key]==null?'—':last[key].toFixed(1)+'%')).join(' · ');
      if((last.errors||[]).length)notice.textContent=last.errors.join('; ');draw();
    }catch(error){values.textContent=t('Нет данных','Unavailable');notice.textContent=error.message;charts.replaceChildren();latest=null;}}
    if(!stopped)timer=setTimeout(update,5000);
  }
  section.addEventListener('toggle',draw);window.addEventListener('pagehide',()=>{stopped=true;clearTimeout(timer)});update();
})();
