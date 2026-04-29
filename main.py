"""
main executable
imports all other scripts and runs them in correct order
"""


#IMPORTS:
#Local
from collector.event_logs import wev_run, file_path
from collector.brow_hist import get_history, path, write_history
from utils.logger import log_setup
from parsers import path_find, file_parser, scoring, write_json_report, timer, search_history, brow_report


#Standard
import logging
import time


#styling
from time import sleep
from rich import print as rprint
from rich.console import Console
console = Console()


banner = (r"""                                                   
     /.\      '||''''| |''||''| |''||''|    XXX    
    // \\      ||  .      ||       ||      X   X   
   //...\\     ||''|      ||       ||       XXXX   
  //     \\    ||         ||       ||           X  
 //       \\   ||         ||       ||            X """)


def main():
    try:
        rprint(f"[white on rgb(0,0,143)][bold]{banner}\n Automated Forensics Triage Tool                   \n[/white on rgb(0,0,143)][/bold][white on rgb(0,0,50)][italic] By Sonny Bowers & Jane Rewnwick                   \n[white on rgb(0,0,50)][italic]")
        while True:
            log_setup()
            start = console.input("\n\nScan Security Event Logs (1)\nScan Chrome Browser History (2)\n\nEnter: ")
            if start == '1':
                try:
                    evtx_file = file_path()
                except Exception as e:
                    logging.error("%s", e)
                    evtx_file = '/tmp/default.evtx'
                try:   
                    wev_run(evtx_file)
                except FileNotFoundError as e:
                    logging.error("%s", e)
                    logging.info("%s", "[HINT] - 'wevutil can only be run on windows")
                except Exception as e:
                    logging.error("%s", e)

                print("")

                # Configurable thresholds  
                while True:
                    try:        
                        risk_threshold = int(input("Set risk threshold for failed login attempts: "))
                        if risk_threshold < 0 :
                            raise ValueError(' - Cant be a negative number')
                        break
                    except Exception as e:
                        print('Invalid Threshold - ', e) 
                while True:
                    try:        
                        time_window_minutes = int(input("Set time window in minutes for rolling analysis (default 5): ") or 5)
                        if time_window_minutes < 0 :
                            raise ValueError(' - Cant be a negative number')
                        break
                    except Exception as e:
                        print('Invalid Time Window - ', e) 

                sleep(0.5)
                #timer
                overall_start = time.time()


                #path find
                evtx_path, report_output_path, attempts_output_path = path_find()


                # Parsing phase
                parse_start = time.time()
                try:
                    filtered_artifacts, raw_events, failed_count = file_parser(evtx_path, attempts_output_path)
                except Exception as e:
                    loggin.error("%s", e)
                parse_end = time.time()
                parse_secs, parse_mins, parse_hrs = timer(parse_start, parse_end)


                # Scoring phase
                sleep(1)
                score_start = time.time()
                risky_ips = scoring(filtered_artifacts, risk_threshold, time_window_minutes)
                score_end = time.time()
                score_secs, score_mins, score_hrs = timer(score_start, score_end)

                print("")
                sleep(1)
                rprint("[bold][rgb(255,0,120)]================ Info ==============================[/rgb(255,0,120)][/bold]")
                logging.info(f"Parsing duration: {parse_hrs}h {parse_mins}m {parse_secs}s")
                logging.info(f"Scoring duration: {score_hrs}h {score_mins}m {score_secs}s")


                # Overall timing
                overall_end = time.time()
                total_secs, total_mins, total_hrs = timer(overall_start, overall_end)
                total_elapsed = overall_end - overall_start
                logging.info(f"Total execution duration: {total_hrs}h {total_mins}m {total_secs}s")

                
                # JSON report
                sleep(1)
                write_json_report(raw_events, risky_ips, risk_threshold, time_window_minutes, total_elapsed, report_output_path)
                exit()


            elif start == '2':                
                try:
                    results = get_history()
                    output_path = path()
                    write_history(results, output_path)
                    paths = brow_path_find()
                    browser_path = paths[3]
                    browser_output_path = paths[4]
                    print(browser_path)

                    keyword = input('\nWhat Keyword would you like to search for: ')
                    results = search_history(str(browser_path), keyword)

                    brow_report(results, browser_output_path)
                except FileNotFoundError:
                    logging.error('History not found[')
                    results, output_path = [], '/tmp/history.json'
                except Exception as e:
                    logging.exception(f'{e} \n')
                

            else:
                exit()
    except KeyboardInterrupt:
                exit()



if __name__ == "__main__":
    main()
