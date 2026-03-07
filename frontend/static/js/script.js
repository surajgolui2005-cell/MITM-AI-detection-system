// ---------------------
// GET STATISTICS
// ---------------------

async function getStatistics(){

try{

const response = await fetch("http://localhost:5000/get_statistics")

const data = await response.json()

document.getElementById("packet-count").innerText = data.packets

document.getElementById("attack-count").innerText = data.attacks

}catch(error){

console.log("API not connected")

}

}



// ---------------------
// GET PACKETS
// ---------------------

async function getPackets(){

try{

const response = await fetch("http://localhost:5000/get_packets")

const packets = await response.json()

const table = document.getElementById("packet-table")

table.innerHTML = ""

packets.forEach(packet => {

table.innerHTML += `

<tr>
<td>${packet.time}</td>
<td>${packet.src}</td>
<td>${packet.dst}</td>
<td>${packet.protocol}</td>
<td>${packet.status}</td>
</tr>

`

})

}catch(error){

console.log("Packet API not available")

}

}



// ---------------------
// GET ALERTS
// ---------------------

async function getAlerts(){

try{

const response = await fetch("http://localhost:5000/get_alerts")

const alerts = await response.json()

const alertBox = document.getElementById("alert-box")

alertBox.innerHTML=""

alerts.forEach(alert => {

alertBox.innerHTML += `

<div class="alert alert-danger">
${alert.message}
</div>

`

})

}catch(error){

console.log("Alert API not available")

}

}



// ---------------------
// CHART.JS GRAPH
// ---------------------

const ctx = document.getElementById('attackChart')

const attackChart = new Chart(ctx,{

type:'bar',

data:{

labels:['ARP Spoof','DNS Spoof','SSL Strip'],

datasets:[{

label:'Attacks Detected',

data:[0,0,0]

}]

}

})



// ---------------------
// AUTO REFRESH
// ---------------------

setInterval(()=>{

getStatistics()

getPackets()

getAlerts()

},3000)