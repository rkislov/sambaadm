/* Column selection is local to this browser; filters never change directory data. */
(function(){
 'use strict';
 window.sambaadmTableTools=function({container,table,columns,key,onChange,onReset=()=>{}}){
  const ru=document.documentElement.lang==='ru',t=(a,b)=>ru?a:b;
  const el=(tag,text='')=>{const e=document.createElement(tag);e.textContent=text;return e;};
  const storageKey='sambaadm.columns.v1:'+key,known=new Set(columns.map(c=>c.key));let visible=new Set(columns.filter(c=>c.defaultVisible!==false).map(c=>c.key));
  try{const saved=JSON.parse(localStorage.getItem(storageKey));if(Array.isArray(saved)){const selected=saved.filter(k=>known.has(k));if(selected.length)visible=new Set(selected);}}catch(_){}
  table.classList.add('configured-table');
  const filters=new Map(),inputs=new Map(),checks=new Map();container.classList.add('table-tools');
  function details(title){const d=el('details'),s=el('summary',title),body=el('div');body.className='table-tools-options';d.append(s,body);container.append(d);return body;}
  const columnBox=details(t('Колонки','Columns')),filterBox=details(t('Фильтры по колонкам','Column filters'));
  function persist(){try{localStorage.setItem(storageKey,JSON.stringify([...visible]));}catch(_){} }
  function updateChecks(){for(const [key,input]of checks){input.checked=visible.has(key);input.disabled=visible.size===1&&input.checked;}}
  for(const column of columns){
   const label=el('label',column.label),check=el('input');check.type='checkbox';check.setAttribute('aria-label',t('Показывать колонку ','Show column ')+column.label);label.prepend(check);columnBox.append(label);checks.set(column.key,check);
   check.addEventListener('change',()=>{if(check.checked)visible.add(column.key);else if(visible.size>1)visible.delete(column.key);updateChecks();persist();onChange();});
   const filterLabel=el('label',column.label),input=el(column.choices?'select':'input');input.setAttribute('aria-label',t('Фильтр ','Filter ')+column.label);
   if(column.choices){const all=el('option',t('Все значения','All values'));all.value='';input.append(all);for(const [value,label]of column.choices){const option=el('option',label);option.value=value;input.append(option);}}
   else input.type='search';
   filterLabel.append(input);filterBox.append(filterLabel);inputs.set(column.key,input);
   input.addEventListener(column.choices?'change':'input',()=>{filters.set(column.key,input.value);onChange();});
  }
  function action(label,parent,fn){const b=el('button',label);b.type='button';b.addEventListener('click',fn);parent.append(b);}
  action(t('Все колонки','Show all columns'),columnBox,()=>{visible=new Set(known);updateChecks();persist();onChange();});
  action(t('Сбросить фильтры','Clear filters'),filterBox,()=>{filters.clear();for(const i of inputs.values())i.value='';onReset();onChange();});updateChecks();
  const normalize=value=>String(value??'').normalize('NFKC').toLocaleLowerCase().trim();
  return {
   matches(row,display=(_key,value)=>value){for(const column of columns){const needle=filters.get(column.key);if(!needle)continue;const value=row[column.key];if(column.choices){if(String(value)!==needle)return false;}else if(!normalize((Array.isArray(value)?value.join('; '):value)+' '+display(column.key,value)).includes(normalize(needle)))return false;}return true;},
   apply(){for(const cell of table.querySelectorAll('[data-column]'))cell.hidden=!visible.has(cell.dataset.column);},
   count(){return visible.size;}
  };
 };
})();
