import streamlit as st 
import re 

st.set_page_config(page_title="password Strenght cheaker",page_icon="🔒")

st.title("🔐 password Strenght cheaker")
st.markdown("""
## welcome to the unlimate password strenght cheaker!👋
use this simple tool to check the strenght of your password and get suggestions on how to make it stronger.
            we will give you helpful tips to create a **strong Password** 🔒""")
st.markdown('<h1 style="color:blue">Devan Das Mehrani AI Student</h1>' , unsafe_allow_html=True)
password = st.text_input("enter your passord", type="password")

feedback =[]

score= 0

if password:
    if len(password) >=8:
        score += 1
else :
    feedback.append("❌password should be at least 8 characters long.")

if re.search('[A-Z]', password) and re.search(r'[a-z]', password):
   score += 1
else:
    feedback.append("❌Password should contain both upper and lower case characters.")

if re.search(r'/d', password):
   score += 1
else:
     feedback.append("❌Password should contain at least one dight.")
if re.search(r'[!@$%^&*]',password):

        score += 1
else:
         feedback.append("password should contain at least one special character(!@$%^&*').")
if score == 4:
        feedback.append("✅your password is strong!🎉")    
elif score == 3:
        feedback.append("🟡your password is meduim strenght. It could be stronger.")   
else:     
         feedback.append("🔴your password is weak. please make it stronger.")
if feedback:
       st.markdown("## Improvements suggestions") 
       for tip in feedback:
           st.write(tip)  
else:
    st.info("please enter your password to get strated.")
           