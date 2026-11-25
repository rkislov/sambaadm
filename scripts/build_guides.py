"""Build illustrated Word manuals from docs/admin.md and docs/user.md.
Requires python-docx. Run from any directory; render resulting DOCX for layout QA.
"""
from pathlib import Path
import re
from urllib.parse import urljoin
from docx import Document
from docx.shared import Cm, Pt, RGBColor
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
ROOT = Path(__file__).resolve().parents[1]

def inline(paragraph, text, source):
    """Keep links usable without appending long URLs to every paragraph."""
    base = 'https://github.com/rkislov/sambaadm/blob/main/' + str(source.relative_to(ROOT))
    offset = 0
    for match in re.finditer(r'\[([^]]+)\]\(([^)]+)\)|`([^`]+)`|\*\*([^*]+)\*\*', text):
        paragraph.add_run(text[offset:match.start()])
        if match.group(1):
            from docx.opc.constants import RELATIONSHIP_TYPE as RT
            link = OxmlElement('w:hyperlink')
            link.set(qn('r:id'), paragraph.part.relate_to(urljoin(base, match.group(2)), RT.HYPERLINK, is_external=True))
            run = OxmlElement('w:r');props = OxmlElement('w:rPr')
            style = OxmlElement('w:rStyle');style.set(qn('w:val'), 'Hyperlink');props.append(style);run.append(props)
            value = OxmlElement('w:t');value.text = match.group(1);run.append(value);link.append(run);paragraph._p.append(link)
        else:
            run = paragraph.add_run(match.group(3) or match.group(4))
            if match.group(3):run.font.name='Courier New';run.font.size=Pt(9)
            else:run.bold=True
        offset = match.end()
    paragraph.add_run(text[offset:])

def plain(s):
    return re.sub(r'\[([^]]+)\]\([^)]+\)', r'\1', s).replace('`', '').replace('**', '')

def markdown_lines(text):
    """Preserve blocks while joining Markdown soft wraps into Word paragraphs."""
    paragraph=[]
    code=False
    for line in text.splitlines():
        boundary=(not line or code or line.startswith(('```','#','![','- ','* ')) or re.match(r'^\d+\. ',line))
        if boundary:
            if paragraph:
                yield ' '.join(paragraph)
                paragraph=[]
            yield line
            if line.startswith('```'):
                code=not code
        else:
            paragraph.append(line)
    if paragraph:
        yield ' '.join(paragraph)

def build(source, target):
    doc = Document()
    sec = doc.sections[0]
    sec.page_width, sec.page_height = Cm(21), Cm(29.7)
    sec.top_margin = Cm(1.65)
    sec.bottom_margin = Cm(2.1)
    sec.left_margin = sec.right_margin = Cm(1.905)
    for name, size in [('Normal',10.5),('Title',26),('Heading 1',16),('Heading 2',12),('Caption',9)]:
        st=doc.styles[name];st.font.name='Arial';st.font.size=Pt(size);st.font.color.rgb=RGBColor(0,0,0)
        st.paragraph_format.space_after=Pt(7)
    doc.styles['Normal'].paragraph_format.line_spacing=1.08
    doc.styles['Heading 1'].paragraph_format.space_before=Pt(15)
    doc.styles['Heading 2'].paragraph_format.space_before=Pt(10)
    footer=sec.footer.paragraphs[0];footer.alignment=2
    r=footer.add_run('sambaadm  |  ');r.font.size=Pt(8)
    fld=OxmlElement('w:fldSimple');fld.set(qn('w:instr'),'PAGE');footer._p.append(fld)
    for el in doc.styles.element.iter():
        for child in list(el):
            if child.tag == qn('w:pBdr'): el.remove(child)
    headings=[line[3:] for line in source.read_text().splitlines() if line.startswith('## ')]
    code=False
    contents=False
    code_lines=[]
    for line in markdown_lines(source.read_text()):
        if not line: continue
        if line.startswith('```'):
            if code:
                p=doc.add_paragraph('\n'.join(code_lines))
                p.paragraph_format.space_after=Pt(7)
                p.paragraph_format.line_spacing=1
                p.paragraph_format.keep_together=True
                for r in p.runs:r.font.name='Courier New';r.font.size=Pt(8)
                code_lines=[]
            code=not code
            continue
        if code:
            code_lines.append(line)
            continue
        if line.startswith('# '): doc.add_paragraph(line[2:],'Title');continue
        if line.startswith('## '):
            if not contents:
                doc.add_paragraph('Содержание', 'Heading 2')
                for title in headings:
                    entry=doc.add_paragraph(title)
                    entry.paragraph_format.space_after=Pt(1)
                    for run in entry.runs: run.font.size=Pt(9)
                contents=True
            p=doc.add_paragraph(line[3:],'Heading 1')
            if line[3:] in (headings[0], 'Развёртывание нового домена и контроллеров'): p.paragraph_format.page_break_before=True
            continue
        if line.startswith('### '): doc.add_paragraph(line[4:],'Heading 2');continue
        m=re.match(r'!\[(.*?)\]\((.*?)\)',line)
        if m:
            p=doc.add_paragraph();p.paragraph_format.keep_with_next=True
            if "share-wizard" in m[2]: p.alignment=1
            picture=p.add_run().add_picture(str(source.parent/m[2]),width=Cm(13.5 if 'share-wizard' in m[2] else 17.0))
            picture._inline.docPr.set('descr',m[1])
            doc.add_paragraph(m[1], 'Caption');continue
        if line.startswith('[Иллюстрированная') or line.startswith('[Инструкция Word'): continue
        p=doc.add_paragraph()
        inline(p,line,source)
        if code:
            p.paragraph_format.space_after=Pt(0)
            p.paragraph_format.line_spacing=1
            for r in p.runs:r.font.name='Courier New';r.font.size=Pt(8)
    paragraphs=doc.paragraphs
    for i,p in enumerate(paragraphs[:-1]):
        if p.text.rstrip().endswith(':'): p.paragraph_format.keep_with_next=True
    doc.core_properties.title=doc.paragraphs[0].text
    doc.core_properties.author='sambaadm'
    version=re.search(r'Версия [0-9.]+ от [^.]+', source.read_text())
    doc.core_properties.subject=version.group(0) if version else 'Руководство sambaadm'
    target.parent.mkdir(parents=True,exist_ok=True);doc.save(target)

if __name__ == '__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('guides',nargs='*',choices=['admin','user','domain-init'])
    args=parser.parse_args()
    for guide in args.guides or ['admin','user','domain-init']:
        build(ROOT/('docs/'+guide+'.md'),ROOT/('docs/'+guide+'-guide/sambaadm-'+guide+'-guide.docx'))
