import pygeoip              
import gmplot
import webbrowser
import dpkt
import socket


gip=pygeoip.GeoIP('GeoLiteCity.dat')  


from dpkt.compat import compat_ord

def mac_addr(address):   
   
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):   
    
    
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def print_packets(pcap):
    t=0
    mylist=[]
    for timestamp, buf in pcap:
        t=t+1
        if t==200000: 
            
            break

        eth = dpkt.ethernet.Ethernet(buf)   
        

        if not isinstance(eth.data, dpkt.ip.IP):   
            
            continue
        
        ip = eth.data     
        c=inet_to_str(ip.src)      
        
        mylist.append(c)    
    d=set(mylist)     
    
    d1=list(d)        
    latitude_list=[]
    longitude_list=[]
    sum1=0;       
    sum2=0;
    n=0;
    for j in d1:

            y=j
            
            r=mylist.count(y)  
            
            
            if(r>50000):   
                
                 
    
                 print(y)
                 res=gip.record_by_addr(y);  
                 
                 
                 n=n+1
                 sum1=sum1+float(res['latitude'])  
                 
                 sum2=sum2+float(res['longitude'])
                 
                 latitude_list.append(res['latitude'])   
                 longitude_list.append(res['longitude'])
                 
                 
    sum1=sum1/n  
    sum2=sum2/n
    
                  
    gmap3 = gmplot.GoogleMapPlotter(sum1, 
                                sum2, 13) 
                  
                
    gmap3.scatter( latitude_list, longitude_list, '# FF0000', 
                                              size = 40, marker = False ) 
                  
               
    gmap3.heatmap(latitude_list, longitude_list) 
                  
    gmap3.draw( "C:\\Users\\Lenovo\\Desktop\\map13.html" ) 
    
 
    url = "C:\\Users\\Lenovo\\Desktop\\map13.html"
    webbrowser.open(url, new=2) 


def main():  
    filename=('maccdc2012_00016.pcap')
    f=open(filename,"rb", buffering=0);
    pcap=dpkt.pcap.Reader(f) 
    print_packets(pcap)