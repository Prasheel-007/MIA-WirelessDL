from django.db.models import Count
from django.db.models import Q
from django.shortcuts import render, redirect, get_object_or_404
import numpy as np
from sklearn.ensemble import VotingClassifier

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.metrics import accuracy_score
import pandas as pd

# Create your views here.
from Remote_User.models import ClientRegister_Model,inference_attack_detection,detection_ratio,detection_accuracy

def login(request):


    if request.method == "POST" and 'submit1' in request.POST:

        username = request.POST.get('username')
        password = request.POST.get('password')
        try:
            enter = ClientRegister_Model.objects.get(username=username,password=password)
            request.session["userid"] = enter.id

            return redirect('ViewYourProfile')
        except:
            pass

    return render(request,'RUser/login.html')

def Register1(request):

    if request.method == "POST":
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        phoneno = request.POST.get('phoneno')
        country = request.POST.get('country')
        state = request.POST.get('state')
        city = request.POST.get('city')
        ClientRegister_Model.objects.create(username=username, email=email, password=password, phoneno=phoneno,
                                            country=country, state=state, city=city)

        return render(request, 'RUser/Register1.html')
    else:
        return render(request,'RUser/Register1.html')

def ViewYourProfile(request):
    userid = request.session['userid']
    obj = ClientRegister_Model.objects.get(id= userid)
    return render(request,'RUser/ViewYourProfile.html',{'object':obj})


def Predict_Membership_Inference_Attack(request):

        if request.method == "POST":

            slno= request.POST.get('slno')
            Flow_ID= request.POST.get('Flow_ID')
            Source_IP= request.POST.get('Source_IP')
            Source_Port= request.POST.get('Source_Port')
            Destination_IP= request.POST.get('Destination_IP')
            Destination_Port= request.POST.get('Destination_Port')
            Protocol= request.POST.get('Protocol')
            Timestamp= request.POST.get('Timestamp')
            Flow_Duration= request.POST.get('Flow_Duration')
            Total_Fwd_Packets= request.POST.get('Total_Fwd_Packets')
            Total_Length_of_Fwd_Packets= request.POST.get('Total_Length_of_Fwd_Packets')
            Fwd_Packet_Length_Max= request.POST.get('Fwd_Packet_Length_Max')
            Fwd_Packet_Length_Min= request.POST.get('Fwd_Packet_Length_Min')
            Flow_Bytes_per_second= request.POST.get('Flow_Bytes_per_second')
            Flow_Packets_per_second= request.POST.get('Flow_Packets_per_second')
            Fwd_Packets_per_second= request.POST.get('Fwd_Packets_per_second')
            Min_Packet_Length= request.POST.get('Min_Packet_Length')
            Max_Packet_Length= request.POST.get('Max_Packet_Length')
            Packet_Length_ean= request.POST.get('Packet_Length_ean')
            ACK_Flag_Count= request.POST.get('ACK_Flag_Count')

            df = pd.read_csv('Datasets.csv', encoding='latin-1')

            def apply_results(label):
                if (label == "No Attack"):
                    return 0
                elif (label == "Poisoning or Causative Attack"):
                    return 1
                elif (label == "Trojan Attack"):
                    return 2
                elif (label == "Evasion or Adversarial Attack"):
                    return 3


            df['label'] = df['Label'].apply(apply_results)


            cv = CountVectorizer()

            X = df['slno']
            y = df["label"]

            print("X Values")
            print(X)
            print("Labels")
            print(y)



            #cv = CountVectorizer(lowercase=False, strip_accents='unicode', ngram_range=(1, 1))
            #X = cv.fit_transform(df['slno'].apply(lambda x: np.str_(X)))

            X = cv.fit_transform(X)

            models = []
            from sklearn.model_selection import train_test_split
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.33, random_state=42)
            X_train.shape, X_test.shape, y_train.shape

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

            classifier = VotingClassifier(models)
            classifier.fit(X_train, y_train)
            y_pred = classifier.predict(X_test)

            slno1 = [slno]
            vector1 = cv.transform(slno1).toarray()
            predict_text = classifier.predict(vector1)

            pred = str(predict_text).replace("[", "")
            pred1 = pred.replace("]", "")

            prediction = int(pred1)

            if prediction == 0:
                val = 'No Attack'
            elif prediction == 1:
                val = 'Poisoning or Causative Attack'
            elif prediction == 2:
                val = 'Trojan Attack'
            elif prediction == 3:
                val = 'Evasion or Adversarial Attack'

            print(val)
            print(pred1)

            inference_attack_detection.objects.create(
            slno=slno,
            Flow_ID=Flow_ID,
            Source_IP=Source_IP,
            Source_Port=Source_Port,
            Destination_IP=Destination_IP,
            Destination_Port=Destination_Port,
            Protocol=Protocol,
            Timestamp=Timestamp,
            Flow_Duration=Flow_Duration,
            Total_Fwd_Packets=Total_Fwd_Packets,
            Total_Length_of_Fwd_Packets=Total_Length_of_Fwd_Packets,
            Fwd_Packet_Length_Max=Fwd_Packet_Length_Max,
            Fwd_Packet_Length_Min=Fwd_Packet_Length_Min,
            Flow_Bytes_per_second=Flow_Bytes_per_second,
            Flow_Packets_per_second=Flow_Packets_per_second,
            Fwd_Packets_per_second=Fwd_Packets_per_second,
            Min_Packet_Length=Min_Packet_Length,
            Max_Packet_Length=Max_Packet_Length,
            Packet_Length_ean=Packet_Length_ean,
            ACK_Flag_Count=ACK_Flag_Count,
            Prediction=val)

            return render(request, 'RUser/Predict_Membership_Inference_Attack.html',{'objs':val})
        return render(request, 'RUser/Predict_Membership_Inference_Attack.html')

