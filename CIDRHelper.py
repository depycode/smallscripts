#coding=UTF-8
import re
import struct
from sys import argv

class CIDRHelper(object):
    def ipFormatChk(self, ip_str):
        pattern = r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        if re.match(pattern, ip_str):
            return True
        else:
            return False

    def masklenChk(self, masklen):
        if masklen > 0 and masklen < 32:
            return True
        else:
            return False

    def Parse(self, ip, masklen):
        if False == self.ipFormatChk(ip) or False == self.masklenChk(masklen):
            exit("子网格式不对或者掩码>32")

        ips = ip.split(".")
        binip = 0
        for id in ips:
            binip = binip << 8
            binip += int(id)

        mask = (1 << 32) - 1 - ((1 << (32 - masklen)) - 1)

        a, b, c, d = struct.unpack('BBBB', struct.pack('>I', (binip & mask)))
        A = ".".join([str(a), str(b), str(c), str(d+1)])
        a, b, c, d = struct.unpack('BBBB', struct.pack('>I', (binip & mask) + (2 << (32 - masklen - 1)) - 1))
        B = ".".join([str(a), str(b), str(c), str(d)])
        return A + "XXXXX" + B

class lzscanner(object):
    def __init__(self):
        self.CIDR = CIDRHelper()

    def exchange_mask(self,mask):
        # 计算二进制字符串中 '1' 的个数
        count_bit = lambda bin_str: len([i for i in bin_str if i == '1'])
        # 分割字符串格式的子网掩码为四段列表
        mask_splited = mask.split('.')
        # 转换各段子网掩码为二进制, 计算十进制
        mask_count = [count_bit(bin(int(i))) for i in mask_splited]
        return sum(mask_count)

    def group(self,line,mode=0):
        r = re.split("\s{1,}",line)
        domain = r[0].strip()
        ip = r[1].strip()
        if mode == 0:
            return domain
        elif mode == 1:
            return ip if len(ip)<16 else 0

    def makeCList(self,tempIp,start=1,end=255):
        return [tempIp+str(temp) for temp in xrange(start,end)]

    def getIp(self,filename):
        ipList = []
        with open(filename,"r") as fp:
            for l in fp.readlines():
                line = self.group(l,mode=1)
                if line != 0:
                    if line.startswith("127") or line.startswith("192.168") or line.startswith("10.") or line.startswith("172") or line.startswith("255.") or line.startswith("169.254"):
                        continue
                    else:
                        ip = re.match(r"\d+\.\d+\.\d+\.", line)
                        ips = self.makeCList(ip.group(0))
                        ipList+=ips

        return sorted(list(set(ipList)))

    def getDomain(self,filename):
        domainList = []
        with open(filename,"r") as fp:
            for d in fp.readlines():
                domain = self.group(d,mode=0)
                domainList.append(domain)

        return sorted(list(set(domainList)))


    def getDomain_Ip(self,filename):
        list1 = self.getIp(filename)
        list2 = self.getDomain(filename)
        ipDomain = list1+list2
        return ipDomain

    def readfile(self,filename):
        with open(filename,"r") as fp:
            x = fp.readlines()
        return x

    def makeIp(self,filename,mode=0):
        iplist = []
        preList = self.readfile(filename)
        for line in preList:
            line = line.strip()
            if line.endswith("/32"):
                line = line.replace("/32","")
            times = len(re.findall(r"\.",line))
            if "-" in line:
                start = re.split("-", line)[0]
                end = re.split("-", line)[1]
                if times == 3:
                    ip = re.match(r"(\d+\.\d+\.\d+\.)(\d+)", start.strip())
                    start = int(ip.group(2))
                    end = int(end.strip())
                    iplist += self.makeCList(ip.group(1),start=start,end=end+1)
                elif times > 3:
                    ipA= re.match(r"(\d+\.\d+\.\d+\.)(\d+)", start.strip())
                    start = int(ipA.group(2))
                    ipB = re.match(r"(\d+\.\d+\.\d+\.)(\d+)", end.strip())
                    end = int(ipB.group(2))
                    iplist += self.makeCList(ipA.group(1),start=start,end=end+1)
            elif "/" in line:
                ip = re.split("/",line)[0].strip()
                netmask = re.split("/",line)[1].strip()
                if netmask.startswith("255."):
                    exchange = self.exchange_mask(netmask)
                    ipres = self.CIDR.Parse(ip,int(exchange))
                else:
                    ipres = self.CIDR.Parse(ip,int(netmask))
                print "子网掩码转换结果 -> "+ipres
                ipA = re.match(r"(\d+\.\d+\.\d+\.)(\d+)", ipres.split("XXXXX")[0].strip())
                ipB = re.match(r"(\d+\.\d+\.\d+\.)(\d+)", ipres.split("XXXXX")[1].strip())
                start = int(ipA.group(2))
                end = int(ipB.group(2))
                iplist += self.makeCList(ipA.group(1), start=start, end=end)
            else:
                if mode == 0:
                    iplist.append(line)
                elif mode == 1:
                    ip = re.match(r"\d+\.\d+\.\d+\.", line)
                    ips = self.makeCList(ip.group(0))
                    iplist += ips

        return sorted(list(set(iplist)))

    def output(self,dstFile,list):
        with open(dstFile,"w") as fp:
            for k,v in enumerate(list):
                if k+1 < len(list):
                    fp.write(v)
                    fp.write("\n")
                else:
                    fp.write(v)


if __name__ == "__main__":
    LZ = lzscanner()
    # print LZ.getDomain("test.txt")
    # print LZ.getIp("test.txt")
    # print LZ.getDomain_Ip("test.txt")
    # print LZ.makeIp("ip.txt")
    if len(argv)<4:
        exit( "Usage : Welcome to CIDRHelper\n" \
              "------------------------------------------------\n" \
              "-d    filename   -o   dstfilename  --full #获取子域名和ip保存到文件\n" \
              "-d    filename   -o   dstfilename  --domain #仅获取子域名保存到文件\n" \
              "-d    filename   -o   dstfilename  --onlyip #仅获取ip保存到文件\n" \
              "-ip   filename   -o   dstfilename #处理子网掩码 eg.*/28, */255.255.255.240, 55.55.55.55-55.55.55.100,23.1.2.100-254\n"
              "-ip   filename   -o   dstfilename --fullip #处理ip时候单个ip也转换为c段\n" \
              "------------------------------------------------")
    elif len(argv)>4:
        if argv[1] == "-d" and argv[3] == "-o":
            print "start 处理子域名扫描结果"
            filename = argv[2]
            dstFilename = argv[4]
            if "--full" in argv:
                LZ.output(dstFilename,LZ.getDomain_Ip(filename))
            elif "--domain" in argv:
                LZ.output(dstFilename, LZ.getDomain(filename))
            elif "--onlyip" in argv:
                LZ.output(dstFilename, LZ.getIp(filename))
            print "success 处理完成"
        elif argv[1] == "-ip" and argv[3] == "-o":
            print "start 处理ip段"
            filename = argv[2]
            dstFilename = argv[4]
            if len(argv) == 5:
                LZ.output(dstFilename,LZ.makeIp(filename))
            elif len(argv) == 6:
                LZ.output(dstFilename,LZ.makeIp(filename,mode=1))

            print "success 处理完成"
        else:
            print "用法错误"
