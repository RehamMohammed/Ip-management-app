from flask import Flask,request
app = Flask(__name__)
from flask_sqlalchemy import SQLAlchemy
import ipaddress
import random , sys


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///subnet.db'
app.config['SQLALCHEMY_BINDS'] = {'ip' : 'sqlite:///ip.db'}
db = SQLAlchemy(app)

class Base(db.Model):
    id = db.Column(db.Integer,primary_key = True)
    VLAN_id = db.Column(db.Integer)
    network_ip = db.Column(db.String(200),nullable = False)
    subnet_mask = db.Column(db.String(200),nullable = False)
    subnet_name = db.Column(db.String(200),nullable = False)

class Subnet(Base,db.Model):
    __tablename__ = 'subnet'

    def __repr__(self):
        return f"{self.id}-{self.VLAN_id} - {self.network_ip} - {self.subnet_mask} - {self.subnet_name}"


class Ip(Base,db.Model):
    __tablename__ = 'ip'

    ip_address = db.Column(db.String(200),nullable = False)
    parent_subnet = Subnet.id
    free = db.Column(db.Boolean)
    used = db.Column(db.Boolean)

    def __repr__(self):
        return f"{self.id}-{self.VLAN_id} - {self.network_ip} - {self.subnet_mask} - {self.subnet_name}-{self.ip_address}-{self.parent_subnet} - {self.free} - {self.used} "

@app.route('/')
def index():
    return 'Hello!'


@app.route('/todo')

#Get Subnets from db
def get_subnets():
    subnets = Subnet.query.all()
    output = []
    for i in subnets:
        data = {'id':i.id,'VLAN_id':i.VLAN_id , 'network_ip':i.network_ip , 'subnet_mask':i.subnet_mask ,'subnet_name':i.subnet_name}
        output.append(data)
    return {"SUBNET" : output}

#Get Ips from db
@app.route('/todo')
def get_ip():
    ips = Ip.query.all()
    ip_table = []
    for i in ips:
        ip_data = {'id':i.id,'VLAN_id':i.VLAN_id , 'network_ip':i.network_ip , 'subnet_mask':i.subnet_mask ,'subnet_name':i.subnet_name,'ip_address':i.ip_address,'parent_subnet':
        i.parent_subnet,'free':i.free,'used':i.used}
        ip_table.append(ip_data)
    return {"IP" : ip_table}

@app.route('/todo/<id>')

#Get Subnet with specific id
def get_subnet(id):
    s = Subnet.query.get_or_404(id)
    return {'VLAN_id':s.VLAN_id,'network_ip':s.network_ip , 'subnet_mask':s.subnet_mask ,'subnet_name':s.subnet_name }

#Add Subnet
@app.route('/todo' , methods = ['POST'])
def add_subnet():
    sub = Subnet(VLAN_id = request.json['VLAN_id'],network_ip = request.json['network_ip'],subnet_mask = request.json['subnet_mask'],subnet_name = request.json['subnet_name'])
    db.session.add(sub)
    db.session.commit()
    return {'id': sub.id}

#Delete Subnet
@app.route('/todo/<id>', methods = ['DELETE'])
def delete_subnet(id):
    s = Subnet.query.get(id)
    if s is None:
        return {"ERROR" : "Invalid Subnet"}
    else:
        db.session.delete(s)
        db.session.commit()
        return {"Message" : "Subnet is deleted"}

#Add/Modify VLAN ID
@app.route('/todo/<id>' , methods = ['POST'])
def add_VLANid(VLANid):
    sub = Subnet(VLAN_id = request.json['VLAN_id'],network_ip = request.json['network_ip'],subnet_mask = request.json['subnet_mask'],subnet_name = request.json['subnet_name'])
    if(VLANid == 0 or VLANid == 4095 or VLANid == 1 or (VLANid >=1002 and VLANid <=1005)):
       return {"ERROR":"This VLAN ID can not be added or modified"}
    sub.VLAN_id = VLANid
    db.session.add(sub)
    db.session.commit()
    return {'VLAN_id':sub.VLAN_id,'network_ip':sub.network_ip , 'subnet_mask':sub.subnet_mask ,'subnet_name':sub.subnet_name }

#Delete VLAN ID
@app.route('/todo/<id>', methods = ['DELETE'])
def delete_vlanid(VLANid):
    subnets = Subnet.query.all()
    for x in subnets:
        if (x.VLAN_id == VLANid):
            if (VLANid == 1 or VLANid == 0 or VLANid == 4095 or (VLANid >=1002 and VLANid <=1005)):
                return {"ERROR":"This VLAN ID can not be deleted"}
            elif (VLANid >=2 and VLANid <=1001):
                db.session.delete(x.VLAN_id)
                db.session.commit()
                return {"Message":"VLAN ID is deleted"}


def convert_to_binary(ip_address):
    ip_add = ip_address.split('.')
    zeros = '00000000'
    s = ''
    for i in range(len(ip_add)):
        x = bin(int(ip_add[i])).replace("0b","")
        if (len(x) < 8):
            x = zeros[:8-(len(x))] + x
        s+= x
    return s

#Calculate first ip address (network address)
def claculate_network_ip(ip_address , subnet_mask):
    ipadd = convert_to_binary(ip_address)
    #if the subnet mask is entered by following its decimal fromat by the ip address we may use this:
    # #network = ipaddress.IPv4Network(ip_address)
    # then get network.broadcast_address
    #assume that subnet mask is entered in string format
    binary_subnet_mask = convert_to_binary(subnet_mask)

    #get first ip address
    first_ip = ''
    for i in range(len(ipadd)):
        res = int(ipadd[i]) & int(binary_subnet_mask[i])
        first_ip+=str(res)
    network_address = ''
    octet1 = int(first_ip[:8],2)
    octet2 = int(first_ip[8:16],2)
    octet3 = int(first_ip[16:24],2)
    octet4 = int(first_ip[24:32],2)
    network_address = octet1 + '.' + octet2 + '.' + octet3 + '.' + octet4
    return network_address

def claculate_broadcast_ip(ip_address , subnet_mask):
    network_add = claculate_network_ip(ip_address,subnet_mask)
    binary_subnet_mask = convert_to_binary(subnet_mask)
    #Toggle the subnet mask
    toggle = ''
    for bit in binary_subnet_mask:
       if (bit == '1'):
          toggle+='0'
       elif (bit == '0'):
          toggle+='1'

    last_ip = ''
    for i in range(len(network_add)):
        res2 = int(network_add[i]) | int(toggle[i])
        last_ip += str(res2)
    broadcast_address = ''
    octet1 = int(last_ip[:8],2)
    octet2 = int(last_ip[8:16],2)
    octet3 = int(last_ip[16:24],2)
    octet4 = int(last_ip[24:32],2)
    broadcast_address = octet1 + '.' + octet2 + '.' + octet3 + '.' + octet4
    return broadcast_address

'''@app.route('/task/<id>')
def get_ip(id):
    ip_a = Ip.query.get_or_404(id)
    return {'VLAN_id':ip_a.VLAN_id,'network_ip':ip_a.network_ip , 'subnet_mask':ip_a.subnet_mask ,'subnet_name':ip_a.subnet_name,'ip_address':ip_a.ip_address,'parent_subnet':ip_a.id,'free':ip_a.free,'used':ip_a.used }'''

#Reserve a free ip given subnet
@app.route('/todo/<id>' , methods = ['POST'])
def reserve_ip(id):
    s = Subnet.query.get_or_404(id)
    ip = Ip.query.get_or_404(id)
    subntMask = s.subnet_mask
    random_ip = str(ipaddress.IPv4Address(random.randint(0,2**32)))
    broadcast = claculate_broadcast_ip(random_ip,subntMask)
    network = claculate_network_ip(random_ip,subntMask)
    if (random_ip != broadcast or random_ip != network):
       ip.used = 1
       ip.free = 0
       return {'ip_address' : ip.ip_address}


#Reserve a specific ip
@app.route('/todo' , methods = ['POST'])
def add_ip(ip):
    ip = Ip(id = request.json['id'],VLAN_id = request.json['VLAN_id'],network_ip = request.json['network_ip'],subnet_mask = request.json['subnt_mask'],subnet_name = request.json['subnet_name'],ip_address = request.json['ip_address'],parent_subnet = request.json['parent_subnet'],free = request.json['free'],used = request.json['used'])
    db.session.add(ip)
    db.session.commit()
    first_octet = int(ip.ip_address[:3])
    binary_ip = convert_to_binary(ip.ip_address)
    if (first_octet == 127 or first_octet >= 224):
         return {"Message" : "Invalid ip address"}
    if (first_octet >= 1 and first_octet <= 126):
        host_portion = binary_ip[8:]
        network_portion = binary_ip[:8]
    elif (first_octet >= 128 and first_octet <= 191):
        host_portion = binary_ip[16:]
        network_portion = binary_ip[:16]
    elif (first_octet >= 192 and first_octet <= 223):
        host_portion = binary_ip[24:]
        network_portion = binary_ip[:24]
    if(int(host_portion,2) == 0 or int(host_portion,2) == 1):
           return {"Message" : "Invalid ip address"}
    if (int(network_portion,2) == 0):
           return {"Message" : "Invalid ip address"}
    
    return {'ip_address' : ip.ip_address}
    

@app.route('/todo/<id>' , methods = ['DELETE'])
def free_ip(id):
    ip = Ip.query.get(id)
    if ip is None:
        return {"ERROR" : "Invalid Ip"}
    else:
       
        db.session.delete(ip)
        db.session.commit()
        return {"Message" : "Ip is Free"}

if __name__ == "__main__":
    app.debug = True
    app.run()
   