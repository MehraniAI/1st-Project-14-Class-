import streamlit as st

st.markdown('<h2><b style="color:green">Unit Converter Assignment</b></h2>', unsafe_allow_html=True)
st.markdown('<h1 style="color:blue">Devan Das Mehrani</h1>', unsafe_allow_html=True)

my_val = st.number_input("Enter value to convert", min_value=0.0, format="%0.3f")

value = st.selectbox("Conversion from", ["Year", "Month", "Week", "Day", "Hour", "Minute","Second"])
to = st.selectbox("Convert to", ["Year", "Month", "Week", "Day", "Hour", "Minute","Second"])

st.markdown(f"Converting from {my_val} {value} to {to}")

btn = st.button("Convert")

def Convertor(my_val, value, to):
    conversion_factors = {
        ("Year", "Month"): 12,
        ("Month", "Year"): 1 / 12,
        ("Year", "Week"): 52,
        ("Week", "Year"): 1 / 52,
        ("Year", "Day"): 360,
        ("Day", "Year"): 1 / 360,
        ("Month", "Week"): 4,
        ("Week", "Month"): 1 / 4,
        ("Month", "Day"): 30,
        ("Day", "Month"): 1 / 30,
        ("Week", "Day"): 7,
        ("Day", "Week"): 1 / 7,
        ("Day", "Hour"): 24,
        ("Hour", "Day"): 1 / 24,
        ("Hour", "Minute"): 60,
        ("Minute", "Hour"): 1 / 60
    }
    
    return my_val * conversion_factors.get((value, to), 1)

if btn:
    conv = Convertor(my_val, value, to)
    st.success(f"Final result: {conv:.3f}")
