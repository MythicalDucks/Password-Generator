# Importing Files
import bcrypt
from tkinter import *
from tkinter import messagebox
import os
from tkinter.ttk import Labelframe
from random import randint
import random
import string


def calculator():
    # Generate Random Strong Password
    def strong_password():
        
        # Clear Our Entry Box
        pw_entry.delete(0, END)

        # Get PW Length and convert to integer
        pw_length = int(my_entry.get())

        # create a variable to hold our password
        my_password = ''

        if var1.get() == 1 and var2.get() == 0 and var3.get() == 0: #Just Letters
            # Loop through password length
            for x in range(pw_length):
                my_password += random.choice(string.ascii_letters)

        elif var1.get() == 0 and var2.get() == 1 and var3.get() == 0: # Just Numbers

            # Loop through password length
            for x in range(pw_length):
                my_password += chr(random.choice(list(range(48,57))))

        elif var1.get() == 0 and var2.get() == 0 and var3.get() == 1: #Just Symbols

            # Loop through password length
            for x in range(pw_length):
                my_password += chr(random.choice(list(range(33, 46)) + list(range(58, 64))))

        elif var1.get() == 1 and var2.get() == 1 and var3.get() == 1: #Any Character

            # Loop through password length
            for x in range(pw_length):
                my_password += chr(random.choice(list(range(34,126))))

        elif var1.get() == 1 and var2.get() == 1 and var3.get() == 0: #Letters and Numbers

            # Loop through password length
            for x in range(pw_length):
                my_password += chr(random.choice(list(range(48,57)) + list(range(65,90))+list(range(97,122))))

        elif var1.get() == 1 and var2.get() == 0 and var3.get() == 1: #Letters and Symbols
            
            # Loop through password length
            for x in range(pw_length):
                my_password += chr(random.choice(list(range(65,90))+list(range(97,122))+list(range(33,46))+list(range(58,64))))

        elif var1.get() == 0 and var2.get() == 1 and var3.get() == 1: #Numbers and Symbols

            # Loop through password length
            for x in range(pw_length):
                my_password += chr(random.choice(list(range(48,57)) + list(range(33, 46)) + list(range(58, 64))))

        else:
            return messagebox.showinfo('Message',f'Please select at least one checkbox below!')	

        # Output password to the screen
        pw_entry.insert(0, my_password)

    def save_password():
        password_window = Tk()
        password_window.geometry('250x250')

        # Label Frame
        labelframe = LabelFrame(password_window, text="Name of Website?")
        labelframe.configure(bg='grey')
        labelframe.pack(pady=20)

        # Create Entry Box To Designate Number of Characters
        my_entry = Entry(labelframe, font=("Helvetica", 24))
        my_entry.pack(pady=20, padx=20)

        # Label Frame
        labelframe2 = LabelFrame(password_window, text="Name of Website?")
        labelframe2.configure(bg='grey')
        labelframe2.pack(pady=20)

        # Create Entry Box To Designate Number of C haracters
        my_entry2 = Entry(labelframe2, font=("Helvetica", 24))
        my_entry2.pack(pady=20, padx=20)
        my_entry2.insert(0,calculatorapp.pw_entry.get())

        # Create a frame for our Buttons
        my_frame = Frame(password_window)
        my_frame.pack(pady=10)
        my_frame.configure(bg='grey')

                # Create our Buttons
        my_button = Button(my_frame, text="Generate Strong Password")
        my_button.grid(row=0, column=0, padx=10)

#my_password += chr(randint(34,126)) - All characters, numbers and symbols

    calculatorapp = Tk()
    calculatorapp.geometry('500x500')
    calculatorapp.title("Password Generator!")
    calculatorapp.configure(bg='grey')

    # Label Frame
    lf = LabelFrame(calculatorapp, text="How Many Characters?")
    lf.configure(bg='grey')
    lf.pack(pady=20)

    pw_entry = Entry(calculatorapp, text='', font=("Helvetica", 24), bd=0, bg="systembuttonface")
    pw_entry.configure(bg ='grey')
    pw_entry.pack(pady=20)



            # Create Entry Box To Designate Number of Characters
    my_entry = Entry(lf, font=("Helvetica", 24))
    my_entry.pack(pady=20, padx=20)

            # Create a frame for our Buttons
    my_frame = Frame(calculatorapp)
    my_frame.pack(pady=10)
    my_frame.configure(bg='grey')

            # Create our Buttons
    my_button = Button(my_frame, text="Generate Strong Password", command=strong_password)
    my_button.grid(row=0, column=0, padx=10)

    
    # Creating Variables for each individual checkbutton
    var1 = IntVar()
    var2 = IntVar()
    var3 = IntVar()

    #Creating Checkbuttons and Frame for them to sit (under the buttons)
    checkbuttonframe = Frame(calculatorapp)
    checkbuttonframe.configure(bg = 'grey')
    checkbuttonframe.pack()
    numbers = Checkbutton(checkbuttonframe, text="Letters", variable=var1, command= strong_password)
    numbers.grid(row=2,column=0)
    letters = Checkbutton(checkbuttonframe, text="Numbers", variable=var2, command= strong_password)
    letters.grid(row=2,column=1)
    symbols = Checkbutton(checkbuttonframe, text="Symbols", variable=var3, command= strong_password)
    symbols.grid(row=2,column=2)



def loginpage():
    def gainAccess(Username=None, Password=None):
        Username = Usernameboxlogin.get()
        Password = Passwordboxlogin.get()
        
        if not len(Username or Password) < 1:
            if True:
                database = open("database.txt", "r")
                d = []
                f = []
                for i in database:
                    a,b = i.split(",")
                    b = b.strip()
                    c = a,b
                    d.append(a)
                    f.append(b)
                    data = dict(zip(d, f))
                try:
                    if Username in data:
                        hashed = data[Username].strip('b')
                        hashed = hashed.replace("'", "")
                        hashed = hashed.encode('utf-8')
                        
                        try:
                            if bcrypt.checkpw(Password.encode(), hashed):
                                loginpage.destroy()
                                calculator()
                            else:
                                return messagebox.showinfo('Message',f"Wrong password")
                            
                        except:
                            return messagebox.showinfo('Message',f"Incorrect passwords or username")
                    else:
                        return messagebox.showinfo('Message',f"Username doesn't exist")
                except:
                    return messagebox.showinfo('Message',f"Password or username doesn't exist")
            else:
                return messagebox.showinfo('Message',f"Error logging into the system")
                
        else:
            return messagebox.showinfo('Message',f"Please attempt login again")
            gainAccess()

    signuppage.destroy()
    loginpage = Tk()
    loginpage.geometry("500x275")
    label = Label(loginpage, text="Welcome Back! Please Login Below:", font =("Arial", 20)).pack()
    label = Label(loginpage, text="Username:", font =("Arial", 20), pady=20).pack()
    Usernameboxlogin = Entry(loginpage)
    Usernameboxlogin.pack()
    label = Label(loginpage, text="Password:", font =("Arial", 20), pady=20).pack()
    Passwordboxlogin = Entry(loginpage)
    Passwordboxlogin.pack()
    Enterappbutton = Button(loginpage, text ="Login!", pady = 20, padx = 20, command=gainAccess).pack()




def register(Username=None, Password1=None, Password2=None):
    Username = usernamebox.get()
    Password1 = passwordbox.get()
    Password2 = passwordrepeatbox.get()
    database = open("database.txt", "r")
    d = []
    for i in database:
        a,b = i.split(",")
        b = b.strip()
        c = a,b
        d.append(a)
    if not len(Password1)<=0:
        database = open("database.txt", "r")
        if not Username ==None:
            if len(Username) <1:
                return messagebox.showinfo('Message',f'Please Provide a Username!')	
            elif Username in d:
                return messagebox.showinfo('Message',f'Username already exists!')		
            else:
                if Password1 == Password2:
                    Password1 = Password1.encode('utf-8')
                    Password1 = bcrypt.hashpw(Password1, bcrypt.gensalt())
                                       
                    database = open("database.txt", "a")
                    database.write(Username+", "+str(Password1)+"\n")
                    return messagebox.showinfo('Message',f'User created successfully! Please Login to Proceed!')

					# print(texts)
                else:
                    return messagebox.showinfo('Message',f'Password does not match!')



signuppage = Tk() 
signuppage.geometry("250x125")

signuppage.title("Signup")
label = Label(signuppage, text="UserName:").grid(column=0, row=0, pady = 5, padx = 5)
usernamebox = Entry(signuppage)
usernamebox.grid(column=1,row=0)

label2 = Label(signuppage, text="Password:").grid(column=0, row=1, pady = 5, padx = 5)
passwordbox = Entry(signuppage)
passwordbox.grid(column=1,row=1)

label3 = Label(signuppage, text="Repeat Password:").grid(column=0, row=2, pady = 5, padx = 5)
passwordrepeatbox = Entry(signuppage)
passwordrepeatbox.grid(column=1,row=2)


Loginbutton = Button(signuppage, text="Login Instead!", command = loginpage).grid(column=0, row=3)
Signupbutton = Button(signuppage, text="Signup!", command=register).grid(column=1,row=3)


# register(Username, Password1, Password2)
# gainAccess(Username, Password1)
register()



# Start Code
signuppage.mainloop()


