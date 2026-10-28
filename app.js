const dialog=document.querySelector('dialog');const content=dialog.querySelector('.dialog-content');let trigger;
document.querySelectorAll('.expand').forEach(button=>button.addEventListener('click',()=>{trigger=button;content.replaceChildren(button.querySelector('.diagram').cloneNode(true),button.closest('figure').querySelector('figcaption').cloneNode(true));dialog.showModal();}));
function closeDrawing(){dialog.close();trigger?.focus();}
dialog.querySelector('.close').addEventListener('click',closeDrawing);
dialog.addEventListener('click',e=>{if(e.target===dialog){const r=dialog.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)closeDrawing();}});
