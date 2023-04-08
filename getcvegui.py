# @Author   : ranyijun@uniontech.com
# @time     : 2023/02/28
# @File     : getcvegui.py
# @Software : PyCharm


# _*_ coding: utf-8 _*_
#include ./bin/python3
#!./bin/python3


from tkinter import *
from tkinter.messagebox import *
from tkinter.filedialog import askdirectory,askopenfilename
from tkinter.ttk import Combobox,Progressbar
from getCveMain import *
import fileToCveNum
import os


INFO={}
INFO["uname"],INFO["password"],INFO['infile'],INFO['outfileDir'],INFO["osversion"]=("","","","","")
cve_items,fail_querys,success_querys= [],[],[]
os_version=""
count = ""
def windows(root):
    """
    定义gui窗口布局
    """

    def getmain():
        """
        主要业务逻辑调用
        """
        global info
        #global cookie,csrftoken

        #print(all_cve)
        #progressbarOne.start()
        """
        判断每个字符是否符合输入标准
        """
        if INFO["uname"] == "" :
            print("选择信息有误，请重新选择用户名")
            showwarning(title="提示",message="用户名没有选择")
            return
        if INFO["uname"][0:2] != "ut" and INFO["uname"][0:2] != "UT":

            print(INFO["uname"][0:2])
            showwarning(title="提示", message="用户名不是ut账号")
            return
        if INFO["password"] =="" :
            print("选择信息有误，请重新选择密码")
            showwarning(title="提示", message="密码没有选择")
            return
        if INFO["infile"]=="" :
            print("选择信息有误，请重新选择输入文件")
            showwarning(title="提示", message="输入文件没有选择")
            return

        if INFO["outfileDir"] =="" :
            print("选择信息有误，请重新选择输出文件夹" )
            showwarning(title="提示", message="输出目录没有选择")
            return
        if INFO["osversion"] =="":
            print("选择信息有误，请重新选择系统版本")
            showwarning(title="提示", message="没有选择系统版本")
            test = "您选择的信息是%s，请详细检查" %INFO

            return

        newInfile = INFO["infile"]
        #index_ = newInfile.index(".")
        index_ = newInfile.rindex(".")
        newInfile_ = newInfile[index_:]
        """
        判断输入文件是什么类型，需要将输入的文件中的cve编号进行提取，并返回all_cve列表，需要所有的getcve函数都是返回列表。
        """
        if newInfile_ == ".txt":
            all_cve = fileToCveNum.txtGetCveNum(INFO["infile"])
        elif newInfile_ == ".doc":
            all_cve = fileToCveNum.docGetCveNum(INFO["infile"])
        elif newInfile_ == ".docx":
            all_cve = fileToCveNum.docxGetCveNum(INFO["infile"])
        elif newInfile_ == ".pdf":
            all_cve = fileToCveNum.pdfGetCveNum(INFO["infile"])
        elif newInfile_ == ".xlsx":
            all_cve = fileToCveNum.xlsxGetCveNum(INFO["infile"])
        else:
            #infile_ = INFO["infile"]
            message = "没有选择合适的输入文件类型，你输入的是%s，请选择txt,doc,docx,xlsx,pdf等"%newInfile_
            #showwarning(title="提示", message="没有选择合适的输入文件类型，请txt,doc,docx,xlsx,pdf等")
            showerror(title="警告",message=message)
            return



        """
        通过输入的ut账号，登录vul网站
        """
        cookie, csrftoken = login_vul(uname=INFO["uname"],pwd=INFO["password"])


        """
        进行主体cve爬取过程，将爬取的cve内容通过xlsx返回并写入到指定文件中
        """
        #global count
        #count = 0
        #if count == 0:
        #progressbarOne.start()
        #progressbarOne['maximum'] = len(all_cve)
        #progressbarOne['value'] = 0


        ###定义进度条最大值，和初始值，每完成一个cve进度条+1，直到所有cve完成为止
        fill_line = canvas.create_rectangle(1.5, 1.5, 0, 23, width=0, fill="red")

        x = len(all_cve)
        n = 400 / x
        print(all_cve,len(all_cve))
        for cve in  range(len(all_cve)):
            n = n + 300 / x
            canvas.coords(fill_line,(0, 0, n, 60))



            print(all_cve[cve])
            desktop_pro_url = 'https://vul.uniontech.com/api/cve/'  # 桌面专业版漏洞库查询url
            server_d = 'https://vul.uniontech.com/api/ent/'  # 服务器企业版
            server_a = 'https://vul.uniontech.com/api/enta/'  # 服务器行业版a
            server_c = 'https://vul.uniontech.com/api/entc/'  # 服务器行业版a,之前的c版
            server_euler = 'https://vul.uniontech.com/api/euler/'  # 欧拉版
            cve=[all_cve[cve]]
            if INFO["osversion"] == "--pro":  # 爬取桌面专业版的cve漏洞信息
                cve_item, success_query, fail_query = query_vul_library(cookie, csrftoken, desktop_pro_url, cve)
                print(cve_item, success_query, fail_query)
                if cve_item:
                    cve_items.append(cve_item[0])
                if success_query:
                    success_querys.append(success_query[0])
                if fail_query:
                    fail_querys.append(fail_query[0])
            elif INFO["osversion"] == "--ent":  # 爬取服务器企业版的cve漏洞信息
                cve_item, success_query, fail_query = query_vul_library(cookie, csrftoken, server_d, cve)
                print(cve_item, success_query, fail_query)
                if cve_item :
                    cve_items.append(cve_item[0])
                if success_query:
                    success_querys.append(success_query[0])
                if fail_query:
                    fail_querys.append(fail_query[0])
            elif INFO["osversion"] == "--hya":  # 爬取服务器行业版a的cve漏洞信息
                cve_item, success_query, fail_query = query_vul_library(cookie, csrftoken, server_a, cve)
                print(cve_item, success_query, fail_query)
                if cve_item:
                    cve_items.append(cve_item[0])
                if success_query:
                    success_querys.append(success_query[0])
                if fail_query:
                    fail_querys.append(fail_query[0])
            elif INFO["osversion"] == "--hyc":  # 爬取服务器行业版c的cve漏洞信息
                cve_item, success_query, fail_query = query_vul_library(cookie, csrftoken, server_c, cve)
                print(cve_item, success_query, fail_query)
                if cve_item:
                    cve_items.append(cve_item[0])
                if success_query:
                    success_querys.append(success_query[0])
                if fail_query:
                    fail_querys.append(fail_query[0])
            elif INFO["osversion"] == "--euler":  # 爬取服务器欧拉版的cve漏洞信息
                cve_item, success_query, fail_query = query_vul_library(cookie, csrftoken, server_euler, cve)
                print(cve_item, success_query, fail_query)
                if cve_item:
                    cve_items.append(cve_item[0])
                if success_query:
                    success_querys.append(success_query[0])
                if fail_query:
                    fail_querys.append(fail_query[0])
            else:
                print("请指定漏洞库参数 --pro / --ent / --hya / --hyc / --euler")
                sys.exit(0)
            #getCveMain(new_cve[i], outfile=info[3], osversion=info[4], cookie=cookie, csrftoken=csrftoken)
            #print(new_cve[i], info[3], info[4], cookie, csrftoken)
            #progressbarOne['value'] += 1
            #progressbarOne.update()
            time.sleep(0.5)
            root.update()

        fill_line = canvas.create_rectangle(1.5, 1.5, 0, 23, width=0, fill="white")
        x = len(all_cve)
        n = 400 / x
        for t in range(x):
            n = n + 300 / x
            # 以矩形的长度作为变量值更新
            canvas.coords(fill_line, (0, 0, n, 60))
            root.update()
            time.sleep(0)  # 时间为0，即飞速清空进度条

        print(cve_items,success_querys,fail_querys)
        result_json = do_json(cve_items)
        outfile_file = INFO["outfileDir"] + "/getCveSave.xlsx"
        save_cve_info(result_json, outfile_file)
        messa = "查询结果：成功%s，查询失败：%s"%(len(success_querys),len(fail_querys))
        showinfo(title="信息",message=messa)


    def selectPath():
        """
        选择输入的文件，需要传递的文件为txt文件，不能是企业的文件
        """
        # path_ = askdirectory()  # 使用askdirectory()方法返回文件夹的路径
        global INFO
        path_ = askopenfilename(title="请选择txt文件")
        if path_ == "":
            path.get()  # 当打开文件路径选择框后点击"取消" 输入框会清空路径，所以使用get()方法再获取一次路径
            # print(path_)
        else:
            # path_ = path_.replace("/", "\\")  # 实际在代码中执行的路径为“\“ 所以替换一下
            path.set(path_)
        INFO["infile"] = path_
        # infile = path_
        # print(path_)
        print(INFO["infile"])

    def openPath():
        """
        输出文件文件保存的文件夹，用来接收结果保存的文件，保存的文件是xlsx
        """
        global INFO
        path_out_ = askdirectory(title="输出文件目录")
        if path_out_ == "":
            path_out.get()
        else:
            path_out.set(path_out_)
        INFO["outfileDir"] = path_out_
        print(INFO["outfileDir"])

    def getos():
        global INFO,os_version
        if text.get() == "服务器10xxa版本":
            INFO['osversion'] = "--hya"
            os_version = "服务器10xxa版本"
        elif text.get() == "服务器10xxd版本":
            INFO['osversion'] = "--ent"
            os_version = "服务器10xxd版本"
        elif text.get() == "服务器10xxe版本":
            INFO['osversion'] = "--euler"
            os_version = "服务器10xxe版本"
        elif text.get() == "服务器100xa版本":
            INFO['osversion'] = "--hyc"
            os_version = "服务器100xa版本"
        elif text.get() == "桌面专业版本":
            INFO['osversion'] = "--pro"
            os_version = "桌面专业版本"
        else:
            print()
        print(INFO['osversion'])



    def show():
        """
        检查所有获取的信息是否合格，不合格需要提示，合格的将信息显示出来
        """
        global INFO

        """
        检查ut账号的权限，判断能不爬取cve，如果能爬取就不提示，如果不能爬取，就需要提示账号有错误，需要先判断账号和密码能不能登录，
        如果能登录，才判断权限。
        """

        INFO['uname'] = e1.get()
        INFO["password"] = e2.get()
        if INFO["uname"] == "" :
            print("选择信息有误，请重新选择用户名")
            showwarning(title="提示",message="用户名没有选择")
            return
        if INFO["uname"][0:2] != "ut" and INFO["uname"][0:2] != "UT":

            print(INFO["uname"][0:2])
            showwarning(title="提示", message="用户名不是ut账号")
            return
        if INFO["password"] =="" :
            print("选择信息有误，请重新选择密码")
            showwarning(title="提示", message="密码没有选择")
            return
        ### 检查输入的用户名和密码能否登录平台
        cookie, csrftoken = login_vul(uname=INFO["uname"], pwd=INFO["password"])
        print("--->"+cookie, csrftoken)
        if cookie == "" or csrftoken == "":
            # print(cookie,csrftoken)
            messages = "用户名或者密码错误，无法访问"
            showerror(title="错误", message=messages)
            return
        ###  检查用户是否有权限爬取
        server_d = 'https://vul.uniontech.com/api/ent/'
        cve = ["CVE-2023-0286"]
        c,s,v = query_vul_library(cookie, csrftoken, server_d, cve)
        #print(s+"-<---")
        if s == "":
            print("账号没有权限，请更换权限")



        ### 判断输入文件的类型，能不能够用于爬取
        if INFO["infile"]=="" :
            print("选择信息有误，请重新选择输入文件")
            showwarning(title="提示", message="输入文件没有选择")
            return
        newInfile = INFO["infile"]
        # index_ = newInfile.index(".")
        index_ = newInfile.rindex(".")
        newInfile_ = newInfile[index_:]

        if newInfile_ == ".txt":
            print("满足")

        elif newInfile_ == ".doc":
            print("满足")
        elif newInfile_ == ".docx":
            print("满足")
        elif newInfile_ == ".pdf":
            print("满足")
        elif newInfile_ == ".xlsx":
            print("满足")
        else:
            # infile_ = INFO["infile"]
            message = "没有选择合适的输入文件类型，你输入的是%s，请选择txt,doc,docx,xlsx,pdf等" % newInfile_
            # showwarning(title="提示", message="没有选择合适的输入文件类型，请txt,doc,docx,xlsx,pdf等")
            showerror(title="警告", message=message)
            return

        ### 检查输出文件的目录，查看是否能够写入，判断权限
        if INFO["outfileDir"] =="" :
            print("选择信息有误，请重新选择输出文件夹" )
            showwarning(title="提示", message="输出目录没有选择")
            return
        ret  = os.access(INFO["outfileDir"],os.W_OK)
        print(ret)
        if ret == False:
            messages = "输出目录无权限，请重新选择目录"
            showerror(title="错误", message=messages)
            return

        if INFO["osversion"] =="":
            print("选择信息有误，请重新选择系统版本")
            showwarning(title="提示", message="没有选择系统版本")
            return


        mess = "选择的信息有：用户名称{}，输入的密码{}，选择的输入文件{}，选择的输出文件{}，选择的系统信息{}".format(
            INFO["uname"], INFO["password"], INFO['infile'], INFO['outfileDir'], os_version)
        showinfo(title="信息", message=mess)
        #progressbarOne.start()









    def dele():
        global os_version
        e1.delete(0, END)
        e2.delete(0, END)
        comb.delete(0, END)
        # e3.delete(0, END)
        # path.set(None)
        # path_out.set(None)
        INFO["uname"],INFO["password"],INFO['infile'],INFO['outfileDir'],INFO["osversion"]=("","","","","")
        os_version = ""
        #progressbarOne.stop()

    ###  定义窗口中用户名，密码输入 输入文件路径，输出文件夹路径，以及系统版本选择，需要手动获取到输入的信息反馈
    Label(root, text="用户名：").grid(row=0, column=0)
    Label(root, text="密码：").grid(row=1, column=0)
    Label(root,text="打开文件路径：").grid(row=2,column=0)
    Label(root, text="选择输出文件目录：").grid(row=3, column=0)
    Label(root, text="选择系统版本：").grid(row=4, column=0)
    Label(root, text="查询结果：").grid(row=16, column=0)
    print()

    path = StringVar()
    path.set(os.path.abspath("."))
    path_out = StringVar()
    path_out.set(os.path.abspath("."))
    print(path,path_out)


    text = StringVar()
    comb = Combobox(root,textvariable=text)
    comb['value'] = ("服务器10xxa版本","服务器10xxd版本","服务器10xxe版本","服务器100xa版本","桌面专业版本")

    ###  定义显示各种输入框和输入框的位置。
    # 导入两个输入框

    e1 = Entry(root)
    e2 = Entry(root)
    Entry(root,textvariable=path,state="readonly").grid(row=2, column=1,ipadx=60)
    Entry(root, textvariable=path_out, state="readonly").grid(row=3, column=1, ipadx=60)
    # 设置输入框的位置
    e1.grid(row=0, column=1)
    e2.grid(row=1, column=1)
    comb.grid(row=4, column=1)
    #Label(root,text="查询结果：").grid(row=16,column=0)


    #设置进度条
    Label(root,text="进度条",).place(x=200,y=400)
    canvas =Canvas(root,width=300,height=22,bg="white")
    canvas.place(x=200,y=400)

    ### 设置按钮

    theButton1 = Button(root, text="获取信息", width=10, command=show)
    theButton2 = Button(root, text="清除所有信息", width=10, command=dele)
    theButton3 = Button(root, text="路径选择", width=10, command=selectPath)
    theButton4 = Button(root, text="输出文件目录", width=10, command=openPath)
    theButton5 = Button(root, text="选择系统", width=10, command=getos)
    #Label(root, text="查询结果：").grid(row=16, column=0)
    theButton6 = Button(root, text="开始查询", width=10, command=getmain)

    ### 设置按钮的位置
    theButton1.grid(row=10, column=0, sticky=W, padx=10, pady=5)
    theButton2.grid(row=10, column=3, sticky=E, padx=10, pady=5)
    theButton3.grid(row=2, column=3, sticky=E, padx=10, pady=5)
    theButton4.grid(row=3, column=3, sticky=E, padx=10, pady=5)
    theButton5.grid(row=4, column=3, sticky=E, padx=10, pady=5)
    theButton6.grid(row=12, column=0, sticky=E, padx=10, pady=5)

if __name__ == '__main__':
    # 获取参数
    """
        
    """
    root = Tk()

    root.title("cve查询库工具")
    root.geometry("600x600")
    windows(root)
    mainloop()