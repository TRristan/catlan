"""Builds the catlan and Kitty logo kit SVGs (kit/ and kitty/kit/). Run: python build.py"""
import math, os
HERE=os.path.dirname(os.path.abspath(__file__))
OR,INK,DARK,LIGHT="#e8772e","#1c1b19","#111110","#edece8"

# --- Symbols: one head on a 256 grid (45° ears, two-arc jaw of radius 56), raised 4u for optical centre.
HEAD="M40 32L96 88H160L216 32V164A56 56 0 0 1 160 220H96A56 56 0 0 1 40 164Z"
circle=lambda cx,cy,r:f"M{cx+r} {cy}A{r} {r} 0 1 0 {cx-r} {cy}A{r} {r} 0 1 0 {cx+r} {cy}Z"
def catlan_sym(eye=18, slot=16):
    """catlan: solid head, one round eye and one wink slot as holes."""
    h=slot/2
    return f"{HEAD} {circle(96,146,eye)} M144 {146-h}H176A{h} {h} 0 0 1 176 {146+h}H144A{h} {h} 0 0 1 144 {146-h}Z"
def kitty_sym(t=24, eye=14, ex=24, ey=152):
    """Kitty: the same head as a t-thick outline (inner edges offset by t, so the ears keep 45°) with two solid eyes."""
    tip=32+t+t*math.sqrt(2); xt=96+t-t*math.sqrt(2); ri=56-t
    inner=(f"M{40+t} {tip:.2f}V164A{ri} {ri} 0 0 0 96 {220-t}H160A{ri} {ri} 0 0 0 {216-t} 164"
           f"V{tip:.2f}L{256-xt:.2f} {88+t}H{xt:.2f}Z")
    return f"{HEAD} {inner} {circle(128-ex,ey,eye)} {circle(128+ex,ey,eye)}"

# --- Wordmarks: geometric lowercase, stroke 20 = ring thickness, x-height 100 (y 0..100), ascender 36, descender 36.
R,r,s=51.5,31.5,20
def ring(cx): return f"{circle(cx,50,R)} M{cx+r} 50A{r} {r} 0 1 1 {cx-r} 50A{r} {r} 0 1 1 {cx+r} 50Z"
def c(cx):
    a=math.radians(40); po=lambda rr,sg:(f"{cx+rr*math.cos(a):.2f}",f"{50+sg*rr*math.sin(a):.2f}")
    (x1,y1),(x2,y2),(x3,y3),(x4,y4)=po(R,-1),po(R,1),po(r,1),po(r,-1)
    return f"M{x1} {y1}A{R} {R} 0 1 0 {x2} {y2}L{x3} {y3}A{r} {r} 0 1 1 {x4} {y4}Z"
rect=lambda x,y0,w,y1:f"M{x} {y0}H{x+w}V{y1}H{x}Z"
t_=lambda x:[rect(x+22,-36,s,100), rect(x,0,64,18)]  # t: crossbar 64 wide, stem 22 in from its left
def k(x):
    # 45° arm (20 thick) from the stem up to the x-height; the leg starts on the arm's centreline so no notch shows
    return [rect(x,-36,s,100), f"M{x+10} 51.72L{x+61.72} 0H{x+90}L{x+10} 80Z",
            f"M{x+30.93} 44.93L{x+45.07} 30.79L{x+114.28} 100H{x+86}Z"]
def y(x):
    # a u (n upside down) whose right stem drops to the descender
    return [f"M{x} 0H{x+20}V55A25 25 0 0 0 {x+70} 55V0H{x+90}V55A45 45 0 0 1 {x} 55Z", rect(x+70,0,s,136)]
CATLAN=dict(name="catlan", x0=10, x1=551, bottom=101.5,  # c sits 10u right: its open side reads as extra space
    wm=[c(61.5), ring(164.5), rect(196,0,s,100), *t_(228), rect(306,-36,s,100), ring(391.5), rect(423,0,s,100),
        rect(461,0,s,100), "M461 45A45 45 0 0 1 551 45V100H531V45A25 25 0 0 0 481 45Z"])
KITTY=dict(name="kitty", x0=0, x1=394, bottom=136,  # the two t crossbars touch: one bar, like a ligature
    wm=[*k(0), rect(128,0,s,100), circle(138,-24,12), *t_(164), *t_(228), *y(304)])

def kit(folder, brand, sym, small, reversed_sym=None):
    os.chdir(os.path.join(HERE, folder))
    n,X0,X1,BOT,WM=brand["name"],brand["x0"],brand["x1"],brand["bottom"],brand["wm"]
    W=X1-X0
    wm=lambda col:"".join(f'<path fill="{col}" fill-rule="evenodd" d="{d}"/>' for d in WM)
    svg=lambda vb,body:f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{vb}"><title>{n}</title>{body}</svg>\n'
    def w(name,txt): open(name,"w",encoding="utf-8").write(txt)
    p=lambda col,d:f'<path fill="{col}" fill-rule="evenodd" d="{d}"/>'
    w(f"{n}-symbol.svg",svg("0 0 256 256",p(OR,sym)))
    w(f"{n}-symbol-black.svg",svg("0 0 256 256",p("#000",sym)))
    w(f"{n}-symbol-small.svg",svg("0 0 256 256",p(OR,small)))
    w(f"{n}-wordmark.svg",svg(f"{X0-2} -38 {W+4} {BOT+40}",wm(INK)))
    # Horizontal: wordmark at 0.75, gap ~44u, x-height+ascender centred on the symbol's optical centre (y 126).
    k=0.75; tx=260-X0*k; ty=126-(137.5*k)/2+36*k; M=24; vw=260+W*k+M-(40-M)
    H=lambda sc,wc,bg="",d=sym:svg(f"{40-M} 0 {vw:.0f} 256",bg+p(sc,d)+f'<g transform="translate({tx} {ty:.2f}) scale({k})">{wm(wc)}</g>')
    w(f"{n}-horizontal.svg",H(OR,INK))
    w(f"{n}-horizontal-black.svg",H("#000","#000"))
    w(f"{n}-horizontal-white.svg",H("#fff","#fff"))
    w(f"{n}-horizontal-dark.svg",H(OR,LIGHT,"",reversed_sym or sym))
    w(f"{n}-horizontal-reversed.svg",H(OR,LIGHT,f'<rect x="{40-M}" y="0" width="{vw:.0f}" height="256" fill="{DARK}"/>',reversed_sym or sym))
    # Stacked: wordmark 0.44 centred under the symbol, gap 28u.
    k2=0.44; sx=128-(X0+W/2)*k2; sy=220+28+36*k2
    w(f"{n}-stacked.svg",svg(f"0 0 256 {sy+BOT*k2+24:.0f}",p(OR,sym)+f'<g transform="translate({sx:.2f} {sy:.2f}) scale({k2})">{wm(INK)}</g>'))
    if reversed_sym: w(f"{n}-symbol-reversed.svg",svg("0 0 256 256",f'<rect width="256" height="256" fill="{DARK}"/>'+p(OR,reversed_sym)))

kit("kit", CATLAN, catlan_sym(), catlan_sym(eye=22, slot=22))
# Kitty's outline looks heavier light-on-dark, so the reversed version is 2u thinner.
kit("kitty/kit", KITTY, kitty_sym(), kitty_sym(t=30, eye=18, ex=26, ey=154), reversed_sym=kitty_sym(t=22))
