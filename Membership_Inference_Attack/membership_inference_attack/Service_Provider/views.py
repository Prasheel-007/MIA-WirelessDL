from django.db.models import  Count, Avg
from django.shortcuts import render, redirect
import xlwt
from django.http import HttpResponse
import numpy as np

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.metrics import accuracy_score
import pandas as pd

# Create your views here.
from Remote_User.models import ClientRegister_Model,inference_attack_detection,detection_ratio,detection_accuracy


def serviceproviderlogin(request):
    if request.method  == "POST":
        admin = request.POST.get('username')
        password = request.POST.get('password')
        if admin == "Admin" and password =="Admin":
            return redirect('View_Remote_Users')

    return render(request,'SProvider/serviceproviderlogin.html')



def View_Membership_Inference_Attack_Prediction(request):

    obj = inference_attack_detection.objects.all()
    return render(request, 'SProvider/View_Membership_Inference_Attack_Prediction.html', {'objs': obj})

def View_Membership_Inference_Attack_Prediction_Ratio(request):
    detection_ratio.objects.all().delete()
    ratio = ""
    kword = 'No Attack'
    print(kword)
    obj = inference_attack_detection.objects.all().filter(Prediction=kword)
    obj1 = inference_attack_detection.objects.all()
    count = obj.count();
    count1 = obj1.count();
    ratio = (count / count1) * 100
    if ratio != 0:
        detection_ratio.objects.create(names=kword, ratio=ratio)

    ratio1 = ""
    kword1 = 'Poisoning or Causative Attack'
    print(kword1)
    obj1 = inference_attack_detection.objects.all().filter(Prediction=kword1)
    obj11 = inference_attack_detection.objects.all()
    count1 = obj1.count();
    count11 = obj11.count();
    ratio1 = (count1 / count11) * 100
    if ratio1 != 0:
        detection_ratio.objects.create(names=kword1, ratio=ratio1)

    ratio12 = ""
    kword12 = 'Trojan Attack'
    print(kword12)
    obj12 = inference_attack_detection.objects.all().filter(Prediction=kword12)
    obj112 = inference_attack_detection.objects.all()
    count12 = obj12.count();
    count112 = obj112.count();
    ratio12 = (count12 / count112) * 100
    if ratio12 != 0:
        detection_ratio.objects.create(names=kword12, ratio=ratio12)

    ratio123 = ""
    kword123 = 'Evasion or Adversarial Attack'
    print(kword123)
    obj123 = inference_attack_detection.objects.all().filter(Prediction=kword123)
    obj1123 = inference_attack_detection.objects.all()
    count123 = obj123.count();
    count1123 = obj1123.count();
    ratio123 = (count123 / count1123) * 100
    if ratio123 != 0:
        detection_ratio.objects.create(names=kword123, ratio=ratio123)

    obj = detection_ratio.objects.all()
    return render(request, 'SProvider/View_Membership_Inference_Attack_Prediction_Ratio.html', {'objs': obj})


def View_Remote_Users(request):
    obj=ClientRegister_Model.objects.all()
    return render(request,'SProvider/View_Remote_Users.html',{'objects':obj})


def charts(request,chart_type):
    chart1 = detection_ratio.objects.values('names').annotate(dcount=Avg('ratio'))
    return render(request,"SProvider/charts.html", {'form':chart1, 'chart_type':chart_type})

def charts1(request,chart_type):
    chart1 = detection_accuracy.objects.values('names').annotate(dcount=Avg('ratio'))
    return render(request,"SProvider/charts1.html", {'form':chart1, 'chart_type':chart_type})

def likeschart(request,like_chart):
    charts =detection_accuracy.objects.values('names').annotate(dcount=Avg('ratio'))
    return render(request,"SProvider/likeschart.html", {'form':charts, 'like_chart':like_chart})

def likeschart1(request,like_chart):
    charts =detection_ratio.objects.values('names').annotate(dcount=Avg('ratio'))
    return render(request,"SProvider/likeschart1.html", {'form':charts, 'like_chart':like_chart})

def Download_Predicted_DataSets(request):

    response = HttpResponse(content_type='application/ms-excel')
    # decide file name
    response['Content-Disposition'] = 'attachment; filename="Predicted_Datasets.xls"'
    # creating workbook
    wb = xlwt.Workbook(encoding='utf-8')
    # adding sheet
    ws = wb.add_sheet("sheet1")
    # Sheet header, first row
    row_num = 0
    font_style = xlwt.XFStyle()
    # headers are bold
    font_style.font.bold = True
    # writer = csv.writer(response)
    obj = inference_attack_detection.objects.all()
    data = obj  # dummy method to fetch data.
    for my_row in data:
        row_num = row_num + 1


        ws.write(row_num, 0, my_row.slno, font_style)
        ws.write(row_num, 1, my_row.Flow_ID, font_style)
        ws.write(row_num, 2, my_row.Source_IP, font_style)
        ws.write(row_num, 3, my_row.Source_Port, font_style)
        ws.write(row_num, 4, my_row.Destination_IP, font_style)
        ws.write(row_num, 5, my_row.Destination_Port, font_style)
        ws.write(row_num, 6, my_row.Protocol, font_style)
        ws.write(row_num, 7, my_row.Timestamp, font_style)
        ws.write(row_num, 8, my_row.Flow_Duration, font_style)
        ws.write(row_num, 9, my_row.Total_Fwd_Packets, font_style)
        ws.write(row_num, 10, my_row.Total_Length_of_Fwd_Packets, font_style)
        ws.write(row_num, 11, my_row.Fwd_Packet_Length_Max, font_style)
        ws.write(row_num, 12, my_row.Fwd_Packet_Length_Min, font_style)
        ws.write(row_num, 13, my_row.Flow_Bytes_per_second, font_style)
        ws.write(row_num, 14, my_row.Flow_Packets_per_second, font_style)
        ws.write(row_num, 15, my_row.Fwd_Packets_per_second, font_style)
        ws.write(row_num, 16, my_row.Min_Packet_Length, font_style)
        ws.write(row_num, 17, my_row.Max_Packet_Length, font_style)
        ws.write(row_num, 18, my_row.Packet_Length_ean, font_style)
        ws.write(row_num, 19, my_row.ACK_Flag_Count, font_style)
        ws.write(row_num, 20, my_row.Prediction, font_style)


    wb.save(response)
    return response

def Train_Test_DataSets(request):

    detection_accuracy.objects.all().delete()

    df = pd.read_csv('Datasets.csv',encoding='latin-1')

    df['label'] = df['Label'].map({'No Attack':0,'Poisoning or Causative Attack':1,'Trojan Attack':2,'Evasion or Adversarial Attack':4})

    #cv = CountVectorizer()

    X = df['slno']
    y = df["label"]

    print("X Values")
    print(X)
    print("Labels")
    print(y)

    #X = cv.fit_transform(X)

    cv = CountVectorizer(lowercase=False, strip_accents='unicode', ngram_range=(1, 1))
    X = cv.fit_transform(df['slno'].apply(lambda x: np.str_(X)))
    #X = cv.fit_transform(X)
    labeled = 'Labeled_Data.csv'
    df.to_csv(labeled, index=False)
    df.to_markdown

    models = []
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.33, random_state=42)
    X_train.shape, X_test.shape, y_train.shape
    print("X_test")
    print(X_test)
    print(X_train)

    print("Naive Bayes")

    from sklearn.naive_bayes import MultinomialNB
    NB = MultinomialNB()
    NB.fit(X_train, y_train)
    predict_nb = NB.predict(X_test)
    naivebayes = accuracy_score(y_test, predict_nb) * 100
    print("ACCURACY")
    print(naivebayes)
    print("CLASSIFICATION REPORT")
    print(classification_report(y_test, predict_nb))
    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, predict_nb))
    detection_accuracy.objects.create(names="Naive Bayes", ratio=naivebayes)


    # SVM Model
    print("SVM")
    from sklearn import svm
    lin_clf = svm.LinearSVC()
    lin_clf.fit(X_train, y_train)
    predict_svm = lin_clf.predict(X_test)
    svm_acc = accuracy_score(y_test, predict_svm) * 100
    print(svm_acc)
    print("CLASSIFICATION REPORT")
    print(classification_report(y_test, predict_svm))
    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, predict_svm))
    models.append(('svm', lin_clf))
    detection_accuracy.objects.create(names="SVM", ratio=svm_acc)


    print("KNeighborsClassifier")
    from sklearn.neighbors import KNeighborsClassifier
    kn = KNeighborsClassifier()
    kn.fit(X_train, y_train)
    knpredict = kn.predict(X_test)
    print("ACCURACY")
    print(accuracy_score(y_test, knpredict) * 100)
    print("CLASSIFICATION REPORT")
    print(classification_report(y_test, knpredict))
    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, knpredict))
    models.append(('KNeighborsClassifier', kn))
    detection_accuracy.objects.create(names="KNeighborsClassifier", ratio=accuracy_score(y_test, knpredict) * 100)

    print("Gradient Boosting Classifier")

    from sklearn.ensemble import GradientBoostingClassifier
    clf = GradientBoostingClassifier(n_estimators=100, learning_rate=1.0, max_depth=1, random_state=0).fit(
        X_train,
        y_train)
    clfpredict = clf.predict(X_test)
    print("ACCURACY")
    print(accuracy_score(y_test, clfpredict) * 100)
    print("CLASSIFICATION REPORT")
    print(classification_report(y_test, clfpredict))
    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, clfpredict))
    models.append(('GradientBoostingClassifier', clf))
    detection_accuracy.objects.create(names="Gradient Boosting Classifier",
                                      ratio=accuracy_score(y_test, clfpredict) * 100)


    obj = detection_accuracy.objects.all()

    return render(request,'SProvider/Train_Test_DataSets.html', {'objs': obj})














