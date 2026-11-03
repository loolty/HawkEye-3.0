(() => {
    const daysEl = document.getElementById('calendarDays');
    if (!daysEl) return;
    const monthLabel = document.getElementById('calendarMonth');
    const selectedInput = document.getElementById('selectedDate');
    const selectedText = document.getElementById('selectedDateText');
    const branchInput = document.getElementById('branch_id');
    const timeInput = document.getElementById('time');
    const typeInput = document.getElementById('type');
    const hint = document.getElementById('calendarHint');
    const bookedTimes = document.getElementById('bookedTimes');
    const today = new Date(); today.setHours(0,0,0,0);
    let viewYear=today.getFullYear(), viewMonth=today.getMonth(), selectedDate='', availability={}, availabilityLoaded=false;
    const pad=n=>String(n).padStart(2,'0');
    const iso=(y,m,d)=>`${y}-${pad(m+1)}-${pad(d)}`;
    const displayDate=value=>{if(!value)return 'Not selected';const [y,m,d]=value.split('-').map(Number);return new Date(y,m-1,d).toLocaleDateString(undefined,{weekday:'short',year:'numeric',month:'short',day:'numeric'});};
    function updateSummary(){
      const option=branchInput.options[branchInput.selectedIndex];
      document.getElementById('summaryBranch').textContent=branchInput.value?option.textContent.trim():'Not selected';
      selectedText.textContent=selectedDate?displayDate(selectedDate):'No date selected';
      document.getElementById('summaryDate').textContent=displayDate(selectedDate);
      document.getElementById('summaryTime').textContent=timeInput.value||'Not selected';
      document.getElementById('summaryType').textContent=typeInput.value; updateBookedTimes();
    }
    function updateBookedTimes(){if(!bookedTimes)return;const times=availability[selectedDate]||[];bookedTimes.textContent=times.length?`Booked/requested times at this branch: ${times.join(', ')}. Choose another time if needed.`:'No appointments currently listed for this date at this branch.';bookedTimes.classList.toggle('has-bookings',times.length>0);}
    async function loadAvailability(){
      availability={}; availabilityLoaded=false; if(!branchInput.value){renderCalendar();hint.textContent='Choose a branch to see booked dates.';updateBookedTimes();return;}
      hint.textContent='Checking branch availability…';
      try{const response=await fetch(`/api/appointment-availability?branch_id=${encodeURIComponent(branchInput.value)}&month=${viewYear}-${pad(viewMonth+1)}`,{headers:{Accept:'application/json'}});const data=await response.json();if(!response.ok||!data.ok)throw new Error(data.error||'Availability could not be loaded.');availability=data.dates||{};availabilityLoaded=true;hint.textContent='Green dates have no listed bookings. Amber dates already have bookings; other times may still be available.';}
      catch(err){hint.textContent='Availability could not be checked. The server will validate your request when submitted.';console.error(err);} renderCalendar();updateBookedTimes();
    }
    function renderCalendar(){
      daysEl.innerHTML='';const first=new Date(viewYear,viewMonth,1).getDay(),total=new Date(viewYear,viewMonth+1,0).getDate();monthLabel.textContent=new Date(viewYear,viewMonth,1).toLocaleDateString(undefined,{month:'long',year:'numeric'});
      for(let i=0;i<first;i++){const blank=document.createElement('span');blank.className='calendar-blank';blank.setAttribute('aria-hidden','true');daysEl.appendChild(blank);}
      for(let day=1;day<=total;day++){const value=iso(viewYear,viewMonth,day),d=new Date(viewYear,viewMonth,day),btn=document.createElement('button'),times=availability[value]||[];btn.type='button';btn.className='calendar-day';btn.textContent=day;btn.setAttribute('aria-label',`${displayDate(value)}${times.length?`, ${times.length} booked time(s)`: ', no listed bookings'}`);if(d.getTime()===today.getTime())btn.classList.add('today');if(times.length){btn.classList.add('has-bookings');btn.title=`Booked/requested times: ${times.join(', ')}`;}else if(branchInput.value&&availabilityLoaded&&d>=today)btn.classList.add('available');if(value===selectedDate){btn.classList.add('selected');btn.setAttribute('aria-pressed','true');}else btn.setAttribute('aria-pressed','false');if(d<today){btn.disabled=true;btn.classList.add('past');}btn.addEventListener('click',()=>{selectedDate=value;selectedInput.value=value;renderCalendar();updateSummary();});daysEl.appendChild(btn);}
      document.getElementById('prevMonth').disabled=viewYear===today.getFullYear()&&viewMonth===today.getMonth();document.getElementById('nextMonth').disabled=viewYear>=today.getFullYear()+2;
    }
    function shiftMonth(delta){viewMonth+=delta;if(viewMonth<0){viewMonth=11;viewYear--;}else if(viewMonth>11){viewMonth=0;viewYear++;}loadAvailability();}
    document.getElementById('prevMonth').addEventListener('click',()=>shiftMonth(-1));document.getElementById('nextMonth').addEventListener('click',()=>shiftMonth(1));
    branchInput.addEventListener('change',()=>{selectedDate='';selectedInput.value='';loadAvailability();updateSummary();});timeInput.addEventListener('input',updateSummary);typeInput.addEventListener('change',updateSummary);
    document.getElementById('bookingForm').addEventListener('submit',event=>{if(!selectedInput.value){event.preventDefault();alert('Please select a date on the calendar.');return;}if(!branchInput.value){event.preventDefault();alert('Please select a clinic branch.');return;}if((availability[selectedDate]||[]).includes(timeInput.value)){event.preventDefault();alert('That time is already booked/requested at this branch. Please choose another time.');}});
    renderCalendar();updateSummary();loadAvailability();
})();