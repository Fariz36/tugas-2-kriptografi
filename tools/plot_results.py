"""Style saved measurements without rerunning experiments: python -m tools.plot_results."""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter, MaxNLocator
import numpy as np

BLUE = '#0072B2'
ORANGE = '#D55E00'
INK = '#172B3A'
MUTED = '#52616D'
GRID = '#E3E9ED'
MODES = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']
NAMES = {'text_utf8.txt':'UTF-8 text', 'image_checker.png':'Binary PNG image',
         'repeated_64k.bin':'Repeated blocks · 64 KiB', 'random_64k.bin':'Random bytes · 64 KiB',
         'random_256k.bin':'Random bytes · 256 KiB'}


def style():
    plt.rcParams.update({'font.family':'DejaVu Sans', 'font.size':10,
        'text.color':INK, 'axes.labelcolor':MUTED, 'xtick.color':MUTED, 'ytick.color':MUTED,
        'axes.spines.top':False, 'axes.spines.right':False,
        'axes.edgecolor':'#AAB7C0', 'axes.linewidth':0.7, 'axes.axisbelow':True,
        'figure.facecolor':'white', 'axes.facecolor':'white',
        'savefig.facecolor':'white', 'pdf.fonttype':42, 'ps.fonttype':42})


def heading(fig, title, subtitle):
    fig.text(0.09,0.965,title,fontsize=19,fontweight='bold',ha='left',va='top')
    fig.text(0.09,0.91,subtitle,fontsize=10,color=MUTED,ha='left',va='top')


def save(fig, folder, name, caption):
    fig.text(0.09,0.025,caption,fontsize=9,color=MUTED,ha='left',va='bottom')
    fig.savefig(folder / (name+'.png'),dpi=300)
    fig.savefig(folder / (name+'.pdf'))
    plt.close(fig)


def histograms(root):
    rows=json.loads((root/'results/histograms.json').read_text())
    for row in rows:
        name,mode=row['file'],row['mode']
        if name.startswith('edge_'):continue
        fig,axes=plt.subplots(2,1,figsize=(10,6.5),sharex=True,sharey=True)
        fig.subplots_adjust(left=.09,right=.97,top=.79,bottom=.15,hspace=.55)
        heading(fig,f'{NAMES.get(name,name)} / {mode}',
                'Byte frequency · matched scales · ciphertext payload excludes header, IV and authentication tag')
        for ax,values,label,color in [(axes[0],row['plaintext'],'Plaintext',ORANGE),
                                      (axes[1],row['ciphertext_payload'],'Ciphertext',BLUE)]:
            frequencies=np.array(values['histogram'])/values['size_bytes']
            ax.bar(range(256),frequencies,width=1,color=color,linewidth=0)
            ax.axhline(1/256,color=MUTED,linewidth=1,linestyle=(0,(4,3)))
            entropy=values['entropy_bits_per_byte']
            ax.set_title(f'{label}   |   {values["size_bytes"]:,} bytes   |   H = {entropy:.4f} bits/byte',
                         loc='left',fontsize=11,fontweight='bold',pad=10)
            ax.set_ylabel('Frequency')
            ax.yaxis.set_major_formatter(PercentFormatter(1,decimals=1))
            ax.grid(axis='y',color=GRID,linewidth=.7)
            ax.set_ylim(bottom=0)
        axes[1].set_xlim(-1,256);axes[1].set_xticks([0,64,128,192,255])
        axes[1].set_xlabel('Byte value')
        save(fig,root/'plots',f'histogram_{name}_{mode}',
             'Dashed line: uniform reference (1/256 per byte). PKCS#7 padding is included in ciphertext frequencies.')


def avalanche(root):
    with (root/'results/avalanche_summary.csv').open() as f:rows=list(csv.DictReader(f))
    fig,axes=plt.subplots(1,2,figsize=(12,6),gridspec_kw={'width_ratios':[1,1.8]})
    fig.subplots_adjust(left=.09,right=.97,top=.75,bottom=.23,wspace=.48)
    heading(fig,'Avalanche: cipher core and operating modes',
            'Mean changed ciphertext bits · plaintext flips in orange · master-key flips in blue')
    for ax,scope,modes in [(axes[0],'core',['BLOCK']),(axes[1],'mode',MODES)]:
        for kind,color,offset in [('plaintext',ORANGE,-.17),('key',BLUE,.17)]:
            subset=[next(r for r in rows if r['scope']==scope and r['mode']==m and r['kind']==kind) for m in modes]
            vals=[float(r['mean_percent']) for r in subset]
            errors=[float(r['stddev_percent']) for r in subset]
            positions=np.arange(len(modes))+offset
            ax.barh(positions,vals,height=.28,color=color,label=kind.title(),
                    xerr=errors,error_kw={'ecolor':INK,'elinewidth':.8,'capsize':2})
            for y,v,e in zip(positions,vals,errors):
                ax.text(v+e+1,y,f'{v:.2f}%',va='center',fontsize=9,color=color)
        ax.set_yticks(range(len(modes)),['Block cipher' if m=='BLOCK' else m for m in modes])
        ax.invert_yaxis();ax.set_xlim(0,65);ax.set_xticks([0,10,20,30,40,50,60])
        ax.set_xlabel('Changed payload bits (%)');ax.grid(axis='x',color=GRID,linewidth=.7)
        ax.set_title('128-bit block · 2,048 trials per kind' if scope=='core' else '640-bit padded payload · 512 trials per mode/kind',
                     loc='left',fontsize=10,fontweight='bold',pad=15)
        if scope=='core':ax.axvline(50,color=MUTED,linestyle=(0,(4,3)),linewidth=1)
    handles,labels=axes[1].get_legend_handles_labels()
    fig.legend(handles,labels,loc='lower left',bbox_to_anchor=(.085,.115),frameon=False,ncol=2)
    save(fig,root/'plots','avalanche',
         'Whiskers: sample SD, not confidence intervals. OFB/CTR flip one payload bit when plaintext changes.\n'
         'Mode percentages reflect propagation and payload length; the 50% reference applies to the cipher core.')


def entropy(root):
    with (root/'results/roundtrips.csv').open() as f:rows=list(csv.DictReader(f))
    files=list(NAMES)
    matrix=np.array([[float(next(r for r in rows if r['file']==name and r['mode']==mode)['ciphertext_entropy'])
                      for mode in MODES] for name in files])
    fig,ax=plt.subplots(figsize=(10,6.2))
    fig.subplots_adjust(left=.30,right=.9,top=.78,bottom=.18)
    heading(fig,'Ciphertext byte entropy across modes',
            'All modes on the same corpus · Shannon entropy · maximum 8 bits/byte')
    im=ax.imshow(matrix,vmin=0,vmax=8,cmap='cividis',aspect='auto')
    ax.set_xticks(range(5),MODES);ax.set_yticks(range(5),[NAMES[f] for f in files])
    ax.tick_params(length=0,pad=10)
    for i in range(5):
        for j in range(5):ax.text(j,i,f'{matrix[i,j]:.4f}',ha='center',va='center',
                                 color='white' if matrix[i,j]<4.5 else INK,fontweight='bold')
    for spine in ax.spines.values():spine.set_visible(False)
    cbar=fig.colorbar(im,ax=ax,fraction=.045,pad=.04);cbar.set_label('Bits per byte')
    save(fig,root/'plots','entropy_comparison',
         'Payload only, including padding. PNG input: 485 bytes; small-sample entropy is biased downward.\n'
         'High marginal byte entropy does not establish cryptographic security.')


def convergence(root):
    history=json.loads((root/'results/sbox_history.json').read_text())
    fig,axes=plt.subplots(1,2,figsize=(11,5.3))
    fig.subplots_adjust(left=.1,right=.96,top=.76,bottom=.22,wspace=.25)
    heading(fig,'S-box search: modest improvement in the objective',
            'One seeded GA → SA run · lower fitness is better · seed 0xC0DEC0DE')
    for ax,phase,color in zip(axes,['GA','SA'],[BLUE,ORANGE]):
        rows=[r for r in history if r['phase']==phase]
        if phase=='GA':rows=[history[0],*rows]
        else:rows=[{**next(r for r in reversed(history) if r['phase']=='GA'),'step':0},*rows]
        ax.step([r['step'] for r in rows],[r['fitness'] for r in rows],where='post',color=color,linewidth=2)
        ax.ticklabel_format(axis='y',style='plain',useOffset=False)
        ax.set_title('Genetic algorithm' if phase=='GA' else 'Simulated annealing',loc='left',fontsize=12,fontweight='bold',pad=12)
        ax.set_xlabel('Generation' if phase=='GA' else 'Swap proposal')
        ax.set_ylabel('Best fitness');ax.grid(axis='y',color=GRID)
        ax.annotate(f'Final: {rows[-1]["fitness"]:.4f}',xy=(rows[-1]['step'],rows[-1]['fitness']),
                    xytext=(-8,14),textcoords='offset points',ha='right',color=color,fontsize=9)
    save(fig,root/'plots','sbox_convergence',
         'Fitness = 1000 × DU − NL + 10 × SAC deviation. Initial 9904.3271 → final 9902.2588.\n'
         'GA: best per generation. SA: best-so-far every 100 proposals. DU remains 10; this is not an optimality proof.')


def key_schedule(root):
    with (root/'results/key_schedule_diffusion.csv').open() as f:rows=list(csv.DictReader(f))
    matrix=np.zeros((128,17))
    for r in rows:matrix[int(r['master_key_bit']),int(r['round_key'])-1]=int(r['changed_bits'])
    fig,ax=plt.subplots(figsize=(10,7))
    fig.subplots_adjust(left=.13,right=.79,top=.81,bottom=.18)
    heading(fig,'Revised key schedule: changes reach K2–K17',
            'Single-bit changes to the experiment master key · exact Hamming distance per round key')
    im=ax.imshow(matrix,vmin=0,vmax=128,cmap='cividis',aspect='auto',interpolation='nearest')
    ax.set_xticks(range(0,17,2),[f'K{i}' for i in range(1,18,2)])
    ax.set_yticks([0,31,63,95,127]);ax.set_xlabel('Round key');ax.set_ylabel('Master-key bit (LSB-first byte indexing)')
    for bit in (31,63,95):
        ax.axhline(bit,color=ORANGE,linewidth=.8)
        ax.annotate(f'Bit {bit}',xy=(16.5,bit),xytext=(8,0),textcoords='offset points',
                    color=ORANGE,va='center',fontsize=9,annotation_clip=False)
    cbar=fig.colorbar(im,ax=ax,fraction=.04,pad=.12);cbar.set_label('Changed bits (out of 128)')
    save(fig,root/'plots','key_schedule_diffusion',
         'Orange markers: formerly discarded bits 31, 63 and 95 now affect generated round keys.\n'
         'Single-key map; 4,096 multi-key comparisons and 96 former collision cases are saved separately.')


def render(root):
    root=Path(root);(root/'plots').mkdir(parents=True,exist_ok=True)
    style()
    histograms(root);avalanche(root);entropy(root);convergence(root);key_schedule(root)
    source=Path(__file__)
    measured=['histograms.json','roundtrips.csv','avalanche_summary.csv','sbox_history.json','key_schedule_diffusion.csv']
    manifest={'command':'python -m tools.plot_results','renderer':str(source.relative_to(Path.cwd())),
              'renderer_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
              'matplotlib':matplotlib.__version__,
              'measurement_hashes':{name:hashlib.sha256((root/'results'/name).read_bytes()).hexdigest() for name in measured},
              'exports':'29 figure pairs: 300-dpi PNG and vector PDF; collected measurements unchanged'}
    (root/'results/visualization_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    index={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*'))
           if p.is_file() and p.name!='artifact_hashes.json'}
    (root/'results/artifact_hashes.json').write_text(json.dumps(index,indent=2)+'\n')
    print('Rendered 29 PNG/PDF figure pairs from saved measurements.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data',type=Path,default=Path('data'))
    render(parser.parse_args().data)
