from . import model

def run_analysis(email_content):
    report = {}

    headers = model.extract_headers(email_content)

    header_flags = model.analyze_headers(headers)
    report['headers'] = header_flags

    link_flags = model.analyze_links(email_content)
    report['links'] = link_flags

    content_flags = model.analyze_content(email_content)
    report['content'] = content_flags

    return report
