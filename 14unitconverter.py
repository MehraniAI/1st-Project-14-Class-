try:
    print("1 - length\n2 - Temperature")
    choise = int(input("Enter Your Choiase:")) # 1 =Length 2= Temperature

    # code for length
    if choise == 1:
        length = float(input("Enter Your lemgth in meter:"))
        print("1 - kilometer \n2 - Feet")
        # take choise as input
        length_choise = int(input("Enter Your Choise:")) # 1 = Kilometer, 2 = meter
        if length_choise == 1:
            print(f"{length/1000} kilometer")
        elif length_choise == 2:
            print(f"{length * 3.28084} Feet")
        else:
            print('Invalid choise')

    # code for temperature
    elif choise == 2:
        temp = float(input("Enter your temperature in celcius :"))
        print(f"{(temp * 9/5) + 32} Farenheit")

    else:
        print('INVALID CHOISE')

except:
    print('Please try again')        